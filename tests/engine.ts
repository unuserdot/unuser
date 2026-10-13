// UNUSER engine, end to end on the local Arcium stack: a wallet deposits USDC once, and from then on a relayer
// sends everything. Positions open out of notes with sealed size and side, a price drop is checked in MPC and
// the marked slots are liquidated, the rest close with only the payout revealed and paid as notes, and every
// note is withdrawn to a fresh wallet. The books balance to the micro-USDC and the depositor is never named again.
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { PublicKey, SystemProgram, Keypair, Transaction, ComputeBudgetProgram, sendAndConfirmTransaction } from "@solana/web3.js";
import { createMint, getOrCreateAssociatedTokenAccount, mintTo, getAccount, TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { Unuser } from "../target/types/unuser";
import { randomBytes } from "crypto";
import {
  getArciumEnv,
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgramId,
  getArciumProgram,
  uploadCircuit,
  RescueCipher,
  deserializeLE,
  getMXEPublicKey,
  getMXEAccAddress,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  getComputationAccAddress,
  getClusterAccAddress,
  getLookupTableAddress,
  x25519,
} from "@arcium-hq/client";
import * as fs from "fs";
import * as os from "os";
import { expect } from "chai";
import { Note, NoteTree, bind, fromBytes, leafOf, loadHash, nullifierOf, ownerOf, proveSpend, randomSecret, releaseProver, toBytes32, u64le } from "../sdk/notes";

const SLOTS = 128;
const BOOK_SPACE = 8 + 16 + 2048 + 8192 + 256 + 256 + 16 + 16 + 8 + 8 + 32 + 32 + 8; // ... market, authority, pending
const MAX_LEV = 10n;
const FEE_BPS = 6n; // 0.06% per leg
const BORROW_BPS_PER_HOUR = 1n;
const KEEPER_BPS = 100n;
const OPEN_FEE = 1_000_000n; // 1 USDC per position
const CAP_BPS = 1_000; // open collateral up to 10% of the pool
const N = Number(process.env.UNUSER_N || "6");
const OUT = process.env.UNUSER_OUT || "logs/gate1.json";
const ZK = { wasm: "zk/spend_js/spend.wasm", zkey: "zk/spend.zkey" };
const USD = 1_000_000n; // micro-USD per USD, also USDC base units
const save = (r: any) => fs.writeFileSync(OUT, JSON.stringify(r, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2));

function rng(seed: number) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}
type Pos = { size: bigint; entry: bigint; coll: bigint; long: boolean; v: bigint };
// w = floor(coll * 1e9 / size), what a trader seals with the size; the circuit derives the threshold from it at the
// fill price (encrypted-ixs, open_pos), and this is that rule in the open.
const wOf = (p: { size: bigint; coll: bigint }) => (p.coll * 1_000_000_000n) / p.size;
function vAt(p: { size: bigint; coll: bigint; long: boolean }, entry: bigint): bigint {
  const w = wOf(p);
  if (p.long) return entry > w ? (10_000n * (entry - w)) / 975_000n : 0n;
  return (10_000n * (entry + w) - 1n) / 1_025_000n;
}
function liqAt(p: Pos, price: bigint): boolean {
  const v = vAt(p, p.entry), px = price / 100n;
  return p.long ? px <= v : px > v;
}
function isLiq(p: Pos, price: bigint): boolean {
  const base = 10_000n * p.coll * 1_000_000_000n;
  return p.long
    ? base + 10_000n * p.size * price <= 10_000n * p.size * p.entry + 250n * p.size * price
    : base + 10_000n * p.size * p.entry <= 10_250n * p.size * price;
}
function threshold(p: { size: bigint; entry: bigint; coll: bigint; long: boolean }): bigint {
  const base = 10_000n * p.coll * 1_000_000_000n;
  const se = 10_000n * p.size * p.entry;
  if (p.long) return se > base ? (se - base) / (9_750n * p.size) / 100n : 0n;
  const d = 10_250n * p.size;
  return ((base + se + d - 1n) / d - 1n) / 100n;
}
// The same arithmetic as close_pnl, in the open.
function payout(p: Pos, exit: bigint, borrowBps: bigint): bigint {
  const up = exit >= p.entry;
  const mag = 10_000n * p.size * (up ? exit - p.entry : p.entry - exit);
  const win = p.long === up;
  const fees = p.size * ((p.entry + exit) * FEE_BPS + p.entry * borrowBps);
  const plus = p.coll * 10_000_000_000_000n + (win ? mag : 0n);
  const minus = fees + (win ? 0n : mag);
  return plus > minus ? (plus - minus) / 10_000_000_000_000n : 0n;
}
function makePositions(n: number, entry: bigint, seed = 23): Pos[] {
  const r = rng(seed);
  const out: Pos[] = [];
  for (let i = 0; i < n; i++) {
    const coll = BigInt(Math.round(100 + 4_900 * r() ** 2)) * USD;
    const lev = 2n + BigInt(Math.floor(r() * 9));
    const size = (coll * lev * 1_000_000_000n) / entry;
    const p = { size, entry, coll, long: r() < 0.5 };
    out.push({ ...p, v: threshold(p) });
  }
  return out;
}

describe("UNUSER engine", () => {
  const envProvider = anchor.AnchorProvider.env();
  const provider = new anchor.AnchorProvider(
    new anchor.web3.Connection(envProvider.connection.rpcEndpoint, "confirmed"), envProvider.wallet,
    { commitment: "confirmed", preflightCommitment: "confirmed" });
  anchor.setProvider(provider);
  const conn = provider.connection;
  const program = anchor.workspace.Unuser as Program<Unuser>;
  const arciumProgram = getArciumProgram(provider);
  const arciumEnv = getArciumEnv();
  const clusterAccount = getClusterAccAddress(arciumEnv.arciumClusterOffset);
  const results: any = { started: new Date().toISOString(), opens: [], checks: [], liquidations: [], closes: [], sizes: {}, cu: {} };

  const seen: { name: string; ev: any; t: number; sig: string }[] = [];
  const sigs = new Set<string>();
  const onEv = (name: string) => (ev: any, _slot: number, sig: string) => {
    if (sigs.has(name + sig)) return;
    sigs.add(name + sig);
    seen.push({ name, ev, t: Date.now(), sig });
  };
  for (const e of ["openEvent", "checkEvent", "liquidatedEvent", "closedEvent"]) program.addEventListener(e as any, onEv(e), "processed");
  async function waitEvent(name: string, after: number, pred: (ev: any) => boolean, timeoutMs = 120_000) {
    const t0 = Date.now();
    for (;;) {
      const hit = seen.find((s) => s.name === name && s.t >= after && pred(s.ev));
      if (hit) {
        seen.splice(seen.indexOf(hit), 1);
        // Events are heard at "processed"; the next step reads state at "confirmed", so wait for it.
        for (;;) {
          const st = (await conn.getSignatureStatuses([hit.sig])).value[0];
          if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) break;
          await new Promise((r) => setTimeout(r, 100));
        }
        return hit;
      }
      if (Date.now() - t0 > timeoutMs) throw new Error(`timeout waiting for ${name}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }
  function queueAccounts(name: string, offset: anchor.BN) {
    return {
      computationAccount: getComputationAccAddress(arciumEnv.arciumClusterOffset, offset),
      clusterAccount,
      mxeAccount: getMXEAccAddress(program.programId),
      mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
      executingPool: getExecutingPoolAccAddress(arciumEnv.arciumClusterOffset),
      compDefAccount: getCompDefAccAddress(program.programId, Buffer.from(getCompDefAccOffset(name)).readUInt32LE()),
    };
  }
  async function initCompDef(name: string, method: string, owner: Keypair) {
    const offset = getCompDefAccOffset(name);
    const compDefPDA = PublicKey.findProgramAddressSync(
      [getArciumAccountBaseSeed("ComputationDefinitionAccount"), program.programId.toBuffer(), offset],
      getArciumProgramId(),
    )[0];
    const mxeAccount = getMXEAccAddress(program.programId);
    const mxeAcc = await arciumProgram.account.mxeAccount.fetch(mxeAccount);
    await (program.methods as any)[method]()
      .accounts({ compDefAccount: compDefPDA, payer: owner.publicKey, mxeAccount,
        addressLookupTable: getLookupTableAddress(program.programId, mxeAcc.lutOffsetSlot) })
      .signers([owner]).rpc({ commitment: "confirmed" });
    const raw = fs.readFileSync(`build/${name}.arcis`);
    await uploadCircuit(provider, name, program.programId, raw, false, 500,
      { skipPreflight: true, preflightCommitment: "confirmed", commitment: "confirmed" });
    console.log(`circuit ${name}: ${raw.length} bytes uploaded`);
  }

  after(releaseProver);

  it("trades with no user account: notes in, sealed positions, notes out", async () => {
    // The house: market authority, LP, oracle and the keeper that fills and settles.
    const owner = readKpJson(process.env.ANCHOR_WALLET || `${os.homedir()}/.config/solana/id.json`);
    await initCompDef("open_pos", "initOpenPosCompDef", owner);
    await initCompDef("chk128", "initChk128CompDef", owner);
    await initCompDef("close_pnl", "initClosePnlCompDef", owner);
    const mxePublicKey = await getMXEPublicKeyWithRetry(provider, program.programId);
    const sk = x25519.utils.randomSecretKey();
    const pk = x25519.getPublicKey(sk);
    const cipher = new RescueCipher(x25519.getSharedSecret(sk, mxePublicKey));
    const hash = await loadHash();

    // Three more wallets. The depositor is the trader's real wallet: it pays USDC in and is never seen again.
    // The relayer sends every trading transaction and holds no USDC. The receiver gets the money at the end.
    const [depositor, relayer, receiver] = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
    for (const k of [depositor, relayer]) await conn.confirmTransaction(await conn.requestAirdrop(k.publicKey, 5e9), "confirmed");
    const mint = await createMint(conn, owner, owner.publicKey, null, 6);
    const tokenOf = async (k: PublicKey) => (await getOrCreateAssociatedTokenAccount(conn, owner, mint, k)).address;
    const [ownerToken, depositorToken, receiverToken, relayerToken] = [await tokenOf(owner.publicKey), await tokenOf(depositor.publicKey),
      await tokenOf(receiver.publicKey), await tokenOf(relayer.publicKey)];
    await mintTo(conn, owner, mint, ownerToken, owner, 10_000_000n * USD);
    const DEPOSITS = [40_000n * USD, 1_500n * USD];
    await mintTo(conn, owner, mint, depositorToken, owner, DEPOSITS.reduce((a, b) => a + b));
    const balOf = async (t: PublicKey) => (await getAccount(conn, t)).amount;

    const pda = (...seeds: (Buffer | Uint8Array)[]) => PublicKey.findProgramAddressSync(seeds, program.programId)[0];
    const [market, vault, oracle, treePda] = ["market", "vault", "test_oracle", "tree"].map((s) => pda(Buffer.from(s)));
    const spentOf = (spend: any) => ({ spent: pda(Buffer.from("spent"), Buffer.from(spend.nullifiers[0])), spent2: pda(Buffer.from("spent"), Buffer.from(spend.nullifiers[1])) });
    // Relayer fees: 0.05 USDC per relayed open, close or withdrawal, each paid as a note the relayer names.
    const FEE = 50_000n;
    const bn = (v: bigint) => new anchor.BN(v.toString());
    const relayerNotes: { secret: bigint; amount: bigint }[] = [];
    const relayerOwner = (amount: bigint) => {
      const secret = randomSecret();
      if (amount > 0n) relayerNotes.push({ secret, amount });
      return Array.from(toBytes32(ownerOf(hash, secret))) as any;
    };
    let price = 150n * USD;
    await program.methods.initTestOracle(new anchor.BN(price.toString())).accounts({ authority: owner.publicKey } as any).rpc();
    const setPrice = async (p: bigint) => {
      price = p;
      await program.methods.setTestPrice(new anchor.BN(p.toString())).accounts({ authority: owner.publicKey, oracle } as any).rpc();
    };
    // Fill delay 0 here: the test oracle publishes at the validator's clock, so a price set right after a request is
    // already inside its window.
    await program.methods.initMarket(Number(FEE_BPS), Number(BORROW_BPS_PER_HOUR), Number(KEEPER_BPS), new anchor.BN(0), 30, new anchor.BN(OPEN_FEE.toString()), CAP_BPS, Number(MAX_LEV), 0, 60)
      .accounts({ authority: owner.publicKey, usdcMint: mint, oracle } as any).rpc();
    const bookKp = Keypair.generate();
    await provider.sendAndConfirm(new Transaction().add(
      SystemProgram.createAccount({ fromPubkey: owner.publicKey, newAccountPubkey: bookKp.publicKey,
        lamports: await conn.getMinimumBalanceForRentExemption(BOOK_SPACE), space: BOOK_SPACE, programId: program.programId }),
      await program.methods.initBook().accounts({ authority: owner.publicKey, market, book: bookKp.publicKey } as any).instruction(),
    ), [owner, bookKp]);
    const book = bookKp.publicKey;
    const LP = 1_000_000n * USD;
    await program.methods.lpDeposit(new anchor.BN(LP.toString())).accounts({ owner: owner.publicKey, market, vault, ownerToken } as any).rpc();

    // The trader's mirror of the note tree, filled from the program's NoteEvents.
    const tree = new NoteTree(hash);
    program.addEventListener("noteEvent" as any, (ev: any) => tree.set(ev.index, fromBytes(ev.leaf)), "confirmed");
    async function indexOfLeaf(leaf: bigint): Promise<number> {
      for (let t0 = Date.now(); Date.now() - t0 < 60_000; await new Promise((r) => setTimeout(r, 50))) {
        const i = tree.indexOf(leaf);
        const chain = (await program.account.tree.fetch(treePda)).nextIndex;
        if (i >= 0 && [...Array(chain).keys()].every((k) => tree.node(0, k) !== 0n) && tree.size === chain) return i;
      }
      throw new Error("leaf never arrived");
    }

    // Every trading transaction goes out through here: `signers[0]` pays, and nothing else signs unless listed.
    const traderTxs: string[] = [];
    async function send(name: string, builder: any, signers: Keypair[], cu = 0): Promise<string> {
      const tx: Transaction = await builder.transaction();
      if (cu) tx.instructions.unshift(ComputeBudgetProgram.setComputeUnitLimit({ units: cu }));
      tx.feePayer = signers[0].publicKey;
      const sig = await sendAndConfirmTransaction(conn, tx, signers, { commitment: "confirmed" });
      traderTxs.push(sig);
      if (!results.sizes[name]) {
        results.sizes[name] = tx.serialize().length;
        results.cu[name] = (await conn.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }))!.meta!.computeUnitsConsumed;
      }
      return sig;
    }

    // 1. Money in. This is the last time the depositor's wallet appears.
    const notes: Note[] = [];
    for (const amount of DEPOSITS) {
      const secret = randomSecret();
      await program.methods.deposit(Array.from(toBytes32(ownerOf(hash, secret))) as any, new anchor.BN(amount.toString()))
        .accounts({ payer: depositor.publicKey, market, tree: treePda, vault, payerToken: depositorToken } as any).signers([depositor]).rpc();
      notes.push({ secret, amount, index: await indexOfLeaf(leafOf(hash, secret, amount)) });
    }
    const [main, small] = notes;
    console.log("deposited", DEPOSITS.map((d) => d / USD).join(" + "), "USDC as two notes");

    const posPda = (slot: number, version = 0) => pda(Buffer.from("pos"), book.toBuffer(), Buffer.from(new Uint16Array([slot]).buffer), Buffer.from(new Uint16Array([version]).buffer));
    type Held = { closeKey: Keypair; payoutSecret: bigint };
    const held = new Map<number, Held>();

    // An open, built by the trader and sent by the relayer. Returns the change note.
    async function buildOpen(slot: number, p: Pos, note: Note) {
      const nonce = randomBytes(16);
      const cts = cipher.encrypt([p.size, wOf(p) + (p.long ? 1n << 40n : 0n)], nonce);
      const h: Held = { closeKey: Keypair.generate(), payoutSecret: randomSecret() };
      const payoutOwner = toBytes32(ownerOf(hash, h.payoutSecret));
      const u16 = (v: number) => Buffer.from(new Uint16Array([v]).buffer);
      const x = bind([Buffer.from("open"), book.toBuffer(), u16(slot), u16(0), Buffer.from(cts[0]), Buffer.from(cts[1]), Buffer.from(pk), nonce,
        h.closeKey.publicKey.toBuffer(), payoutOwner, u64le(FEE), u64le(FEE)]);
      const { spend, change } = await proveSpend(hash, tree, note, p.coll + OPEN_FEE + FEE, x, ZK);
      const method = (closeKey: PublicKey, fee = FEE, pays = true) => program.methods
        .requestOpen(spend as any, slot, 0, cts.map((c) => Array.from(c)) as any, Array.from(pk) as any, new anchor.BN(deserializeLE(nonce).toString()),
          bn(p.coll), closeKey, Array.from(payoutOwner) as any, bn(FEE), bn(fee), relayerOwner(pays ? fee : 0n))
        .accounts({ payer: relayer.publicKey, market, tree: treePda, ...spentOf(spend), book, position: posPda(slot) } as any);
      return { h, change, method };
    }
    async function open(slot: number, p: Pos, note: Note): Promise<{ ok: boolean; change: Note }> {
      const t0 = Date.now();
      const { h, change, method } = await buildOpen(slot, p, note);
      const proveMs = Date.now() - t0;
      await send("request_open", method(h.closeKey.publicKey), [relayer], 400_000);
      held.set(slot, h);
      await setPrice(price); // a price published after the request: inside its window
      const offset = new anchor.BN(randomBytes(8), "hex");
      await program.methods.settleOpen(offset)
        .accountsPartial({ payer: owner.publicKey, ...queueAccounts("open_pos", offset), market, oracle, book, position: posPda(slot) } as any)
        .rpc({ skipPreflight: true });
      const ev = await waitEvent("openEvent", t0, (e) => e.slot === slot);
      results.opens.push({ slot, ok: ev.ev.ok, ms: ev.t - t0, prove_ms: proveMs });
      return { ok: ev.ev.ok, change: { secret: change.secret, amount: change.amount, index: await indexOfLeaf(change.leaf) } };
    }

    // 2. N honest opens, each paid from the change of the one before, so one deposit funds them all.
    const positions = makePositions(N, price);
    let purse = main;
    for (let i = 0; i < N; i++) {
      const r = await open(i, positions[i], purse);
      expect(r.ok).to.equal(true);
      purse = r.change;
    }
    const spentOnOpens = positions.reduce((a, p) => a + p.coll + OPEN_FEE + FEE, 0n);
    expect(purse.amount).to.equal(main.amount - spentOnOpens);
    console.log("opened", N, "positions; change left in the purse:", Number(purse.amount) / 1e6, "USDC (known only to the trader)");

    // 2b. What a relayer or a thief cannot do.
    const probe = makePositions(1, price, 77)[0];
    const refused: Record<string, boolean> = {};
    const fails = async (name: string, f: () => Promise<any>, want: RegExp) => {
      try { await f(); refused[name] = false; } catch (e) { refused[name] = want.test(String(e) + JSON.stringify((e as any).logs ?? "")); if (!refused[name]) console.log(name, String(e)); }
    };
    // The first deposit note is spent; proving from it again still works off chain, but its nullifier is taken.
    await fails("double_spend", async () => { const b = await buildOpen(40, probe, main); await send("x", b.method(b.h.closeKey.publicKey, FEE, false), [relayer], 400_000); }, /already in use/);
    // The relayer swaps in its own close key: the proof no longer matches the order.
    await fails("swapped_close_key", async () => { const b = await buildOpen(40, probe, purse); await send("x", b.method(relayer.publicKey, FEE, false), [relayer], 400_000); }, /BadProof/);
    // The relayer raises its own fee: same.
    await fails("raised_fee", async () => { const b = await buildOpen(40, probe, purse); await send("x", b.method(b.h.closeKey.publicKey, FEE * 10n, false), [relayer], 400_000); }, /BadProof/);
    // A note cannot pay more than it holds: there is no proof to build.
    await fails("overspend", () => proveSpend(hash, tree, small, small.amount + 1n, 1n, ZK), /Assert Failed|Error in template/);
    // A withdrawal bound to one receiver cannot be pointed at another.
    await fails("redirected_withdrawal", async () => {
      const { spend } = await proveSpend(hash, tree, small, 100n * USD, bind([Buffer.from("withdraw"), receiverToken.toBuffer(), u64le(0n)]), ZK);
      await send("x", program.methods.withdraw(spend as any, bn(100n * USD), bn(0n), relayerOwner(0n))
        .accounts({ payer: relayer.publicKey, market, tree: treePda, ...spentOf(spend), vault, receiver: ownerToken } as any), [relayer], 400_000);
    }, /BadProof/);
    // Only the one-time key chosen at the open can ask for the close.
    await fails("stranger_close", () => send("x", program.methods.requestClose(relayerOwner(0n)).accounts({ owner: relayer.publicKey, market, position: posPda(0) } as any), [relayer]), /NotOwner/);
    results.refused = refused;
    console.log("refused", JSON.stringify(refused));
    expect(refused).to.deep.equal({ double_spend: true, swapped_close_key: true, raised_fee: true, overspend: true, redirected_withdrawal: true, stranger_close: true });

    // 2c. An open over the leverage cap is rejected inside MPC; anyone sends the reclaim and the money comes back
    // as a note for the owner named at the open.
    const bad = (() => { const coll = 1_000n * USD; const size = (coll * (MAX_LEV + 2n) * 1_000_000_000n) / price;
      const p = { size, entry: price, coll, long: true }; return { ...p, v: threshold(p) }; })();
    const badOpen = await open(SLOTS - 1, bad, small);
    expect(badOpen.ok).to.equal(false);
    await send("reclaim", program.methods.reclaim().accounts({ payer: relayer.publicKey, market, tree: treePda, book, position: posPda(SLOTS - 1) } as any), [relayer]);
    const refundSecret = held.get(SLOTS - 1)!.payoutSecret;
    // The relayer keeps the fee of the rejected open: it did relay it.
    const refund: Note = { secret: refundSecret, amount: bad.coll + OPEN_FEE, index: await indexOfLeaf(leafOf(hash, refundSecret, bad.coll + OPEN_FEE)) };
    const wallet: Note[] = [purse, badOpen.change, refund];
    console.log("rule breaker rejected; refund note of", Number(refund.amount) / 1e6, "USDC");

    // 3. Price drops to 128: one check round in MPC, then the house settles every marked slot.
    await setPrice(128n * USD);
    const want = positions.map((p, i) => (liqAt(p, price) ? i : -1)).filter((i) => i >= 0);
    let t0 = Date.now();
    const coffset = new anchor.BN(randomBytes(8), "hex");
    await program.methods.chk128(coffset)
      .accountsPartial({ payer: owner.publicKey, ...queueAccounts("chk128", coffset), market, oracle, book } as any)
      .preInstructions([ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 })])
      .rpc({ skipPreflight: true });
    const cev = await waitEvent("checkEvent", t0, () => true);
    const flaggedBits = cev.ev.flagged.reduce((m: bigint, w: any, k: number) => m | (BigInt(w.toString()) << BigInt(64 * k)), 0n);
    const flagged = [...Array(SLOTS).keys()].filter((i) => (flaggedBits >> BigInt(i)) & 1n);
    results.checks.push({ price: 128, ms: cev.t - t0, want, flagged });
    console.log("check at 128:", cev.t - t0, "ms, want", JSON.stringify(want), "flagged", JSON.stringify(flagged));
    expect(flagged).to.deep.equal(want);
    let rewards = 0n;
    for (const i of flagged) {
      const b0 = await balOf(ownerToken);
      await program.methods.liquidate().accounts({ keeper: owner.publicKey, market, vault, keeperToken: ownerToken, book, position: posPda(i) } as any).rpc();
      const got = (await balOf(ownerToken)) - b0;
      rewards += got;
      results.liquidations.push({ slot: i, coll: positions[i].coll, reward: got });
      expect(got).to.equal((positions[i].coll * KEEPER_BPS) / 10_000n);
    }

    // 4. Price recovers to 145: every other position closes. The one-time key signs the request, the relayer pays
    // for it, and the cluster reveals only the payout, which lands as a note.
    await setPrice(145n * USD);
    let payouts = 0n, closeFees = 0n;
    for (const i of positions.map((_, k) => k).filter((k) => !flagged.includes(k))) {
      const t1 = Date.now();
      const h = held.get(i)!;
      const closeRelayer = randomSecret();
      await send("request_close", program.methods.requestClose(Array.from(toBytes32(ownerOf(hash, closeRelayer))) as any)
        .accounts({ owner: h.closeKey.publicKey, market, position: posPda(i) } as any), [relayer, h.closeKey]);
      await setPrice(price);
      const offset = new anchor.BN(randomBytes(8), "hex");
      await program.methods.settleClose(offset)
        .accountsPartial({ payer: owner.publicKey, ...queueAccounts("close_pnl", offset), market, oracle, tree: treePda, book, position: posPda(i) } as any)
        .rpc({ skipPreflight: true });
      const ev = await waitEvent("closedEvent", t1, (e) => e.slot === i);
      const paid = BigInt(ev.ev.payout.toString());
      const expected = payout(positions[i], price, BORROW_BPS_PER_HOUR);
      results.closes.push({ slot: i, ms: ev.t - t1, payout: paid, expected, coll: positions[i].coll });
      expect(paid).to.equal(expected);
      payouts += paid;
      // The payout note is the payout less the close fee, which is a note for the close's relayer.
      const relay = paid < FEE ? paid : FEE;
      if (relay > 0n) relayerNotes.push({ secret: closeRelayer, amount: relay });
      closeFees += relay;
      if (paid > relay) wallet.push({ secret: h.payoutSecret, amount: paid - relay, index: await indexOfLeaf(leafOf(hash, h.payoutSecret, paid - relay)) });
    }
    console.log("closed", results.closes.length, "positions; payouts are notes now");
    for (const i of [...Array(N).keys()]) {
      await program.methods.closeRecord().accounts({ payer: relayer.publicKey, position: posPda(i) } as any).rpc();
    }

    // 5. Money out: the trader's notes leave two at a time (one spend merges two notes) to a wallet that has
    // never touched the exchange, each withdrawal paying the relayer its fee as a note.
    const withdrawTo = async (name: string, from: Note[], to: PublicKey, fee: bigint) => {
      const total = from.reduce((a, n) => a + n.amount, 0n);
      const { spend, change } = await proveSpend(hash, tree, from.length === 2 ? [from[0], from[1]] : from[0], total,
        bind([Buffer.from("withdraw"), to.toBuffer(), u64le(fee)]), ZK);
      await send(name, program.methods.withdraw(spend as any, bn(total - fee), bn(fee), relayerOwner(fee))
        .accounts({ payer: relayer.publicKey, market, tree: treePda, ...spentOf(spend), vault, receiver: to } as any), [relayer], 400_000);
      await indexOfLeaf(change.leaf);
    };
    const mine = wallet.filter((n) => n.amount > 0n);
    let withdrawals = 0;
    for (let k = 0; k < mine.length; k += 2, withdrawals++) await withdrawTo("withdraw", mine.slice(k, k + 2), receiverToken, FEE);
    const got = await balOf(receiverToken);
    const liquidated = flagged.reduce((a, i) => a + positions[i].coll, 0n);
    const paidIn = DEPOSITS.reduce((a, b) => a + b);
    // Everything deposited, minus what the positions cost (collateral, market fee and relayer fee of every open,
    // the rejected one's relayer fee included), plus payouts, minus the relayer fees of closes and withdrawals.
    const expectedOut = paidIn - spentOnOpens - FEE + payouts - closeFees - FEE * BigInt(withdrawals);
    results.money = { deposited: paidIn, withdrawn: got, expected: expectedOut, payouts, liquidated, keeper_rewards: rewards };
    expect(got).to.equal(expectedOut);

    // 5b. The relayer was paid only in notes. It cashes them the same way, two at a time, with no fee to itself.
    const earned: Note[] = [];
    for (const n of relayerNotes) earned.push({ ...n, index: await indexOfLeaf(leafOf(hash, n.secret, n.amount)) });
    for (let k = 0; k < earned.length; k += 2) await withdrawTo("x", earned.slice(k, k + 2), relayerToken, 0n);
    const relayerGot = await balOf(relayerToken);
    results.money.relayer_earned = relayerGot;
    results.money.relayer_notes = earned.length;
    expect(relayerGot).to.equal(paidIn - got - (spentOnOpens - FEE * BigInt(N)) + payouts);

    // 6. Books balance to the micro-USDC: nothing is owed to notes, the vault is exactly the pool.
    const m = await program.account.market.fetch(market);
    const vaultAmount = await balOf(vault);
    results.note_balance_after = BigInt(m.noteBalance.toString());
    results.pool_balance = BigInt(m.poolBalance.toString());
    results.vault = vaultAmount;
    expect(results.note_balance_after).to.equal(0n);
    expect(BigInt(m.openColl.toString())).to.equal(0n);
    expect(vaultAmount).to.equal(results.pool_balance);
    expect(results.pool_balance).to.equal(LP + (paidIn - got - relayerGot) - rewards);
    await program.methods.lpWithdraw(m.lpShares).accounts({ owner: owner.publicKey, market, vault, ownerToken } as any).rpc();
    expect(await balOf(vault)).to.equal(0n);

    // 7. The point of it all: after the deposit, the depositor's wallet and token account appear in no trading
    // transaction, and nothing but the relayer and one-time close keys ever signed one.
    const allowed = new Set([relayer.publicKey.toBase58(), ...[...held.values()].map((h) => h.closeKey.publicKey.toBase58())]);
    let touched = 0, strangers = 0;
    for (const sig of traderTxs) {
      const tx = (await conn.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }))!;
      const keys = tx.transaction.message.getAccountKeys().staticAccountKeys.map((k) => k.toBase58());
      if (keys.includes(depositor.publicKey.toBase58()) || keys.includes(depositorToken.toBase58())) touched++;
      strangers += keys.slice(0, tx.transaction.message.header.numRequiredSignatures).filter((k) => !allowed.has(k)).length;
    }
    results.unlinkable = { trading_transactions: traderTxs.length, naming_the_depositor: touched, signed_by_anyone_else: strangers };
    console.log("unlinkable", JSON.stringify(results.unlinkable));
    expect(touched).to.equal(0);
    expect(strangers).to.equal(0);
    results.finished = new Date().toISOString();
    fs.mkdirSync("logs", { recursive: true });
    save(results);
    console.log("sizes (bytes)", JSON.stringify(results.sizes), "compute units", JSON.stringify(results.cu));
    console.log("deposited", Number(paidIn) / 1e6, "withdrew", Number(got) / 1e6, "USDC; pool", Number(results.pool_balance) / 1e6);
  });
});

async function getMXEPublicKeyWithRetry(provider: anchor.AnchorProvider, programId: PublicKey): Promise<Uint8Array> {
  for (let attempt = 1; attempt <= 600; attempt++) {
    try {
      const k = await getMXEPublicKey(provider, programId);
      if (k) return k;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("Failed to fetch MXE public key");
}

function readKpJson(path: string): Keypair {
  return Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(path).toString())));
}
