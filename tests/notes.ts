// The note layer alone, on a plain local validator (no Arcium needed): deposits become notes, a zero-knowledge
// spend pays a withdrawal and leaves a change note, two notes merge in one spend, the relayer is paid in a note,
// and every way of cheating is refused on chain.
// Run with scripts/test-notes.sh.
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { ComputeBudgetProgram, Keypair, PublicKey, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { createMint, getAccount, getOrCreateAssociatedTokenAccount, mintTo } from "@solana/spl-token";
import { expect } from "chai";
import * as fs from "fs";
import { Unuser } from "../target/types/unuser";
import { Note, NoteTree, bind, fromBytes, leafOf, loadHash, ownerOf, proveSpend, randomSecret, releaseProver, toBytes32, u64le } from "../sdk/notes";

const USD = 1_000_000n;
const ZK = { wasm: "zk/spend_js/spend.wasm", zkey: "zk/spend.zkey" };

describe("UNUSER notes", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const conn = provider.connection;
  const program = anchor.workspace.Unuser as Program<Unuser>;
  const owner = (provider.wallet as any).payer as Keypair;
  after(releaseProver);

  it("deposit, spend, change, withdraw; cheating is refused", async () => {
    const hash = await loadHash();
    const [depositor, relayer, receiver, thief] = [Keypair.generate(), Keypair.generate(), Keypair.generate(), Keypair.generate()];
    for (const k of [depositor, relayer]) await conn.confirmTransaction(await conn.requestAirdrop(k.publicKey, 5e9), "confirmed");
    const mint = await createMint(conn, owner, owner.publicKey, null, 6);
    const tokenOf = async (k: PublicKey) => (await getOrCreateAssociatedTokenAccount(conn, owner, mint, k)).address;
    const [depositorToken, receiverToken, thiefToken, relayerToken] = [await tokenOf(depositor.publicKey), await tokenOf(receiver.publicKey),
      await tokenOf(thief.publicKey), await tokenOf(relayer.publicKey)];
    await mintTo(conn, owner, mint, depositorToken, owner, 10_000n * USD);
    const balOf = async (t: PublicKey) => (await getAccount(conn, t)).amount;

    const pda = (...seeds: (Buffer | Uint8Array)[]) => PublicKey.findProgramAddressSync(seeds, program.programId)[0];
    const [market, vault, oracle, treePda] = ["market", "vault", "test_oracle", "tree"].map((s) => pda(Buffer.from(s)));
    const spentPda = (nullifier: number[]) => pda(Buffer.from("spent"), Buffer.from(nullifier));
    await program.methods.initTestOracle(new anchor.BN(150_000_000)).accounts({ authority: owner.publicKey } as any).rpc();
    await program.methods.initMarket(6, 1, 100, new anchor.BN(0), 30, new anchor.BN(1_000_000), 1_000, 10, 0, 60)
      .accounts({ authority: owner.publicKey, usdcMint: mint, oracle } as any).rpc();

    // The mirror is filled from what the chain says, then checked against the chain's own root.
    const tree = new NoteTree(hash);
    program.addEventListener("noteEvent" as any, (ev: any) => tree.set(ev.index, fromBytes(ev.leaf)), "confirmed");
    const chainTree = () => program.account.tree.fetch(treePda);
    async function indexOfLeaf(leaf: bigint): Promise<number> {
      for (let t0 = Date.now(); Date.now() - t0 < 30_000; await new Promise((r) => setTimeout(r, 50))) {
        const t = await chainTree();
        if (tree.indexOf(leaf) >= 0 && tree.size === t.nextIndex) {
          expect(toBytes32(tree.root()).equals(Buffer.from(t.roots[t.head]))).to.equal(true);
          return tree.indexOf(leaf);
        }
      }
      throw new Error("leaf never arrived");
    }
    const noteBalance = async () => BigInt((await program.account.market.fetch(market)).noteBalance.toString());
    const report: any = {};
    async function send(name: string, builder: any, signers: Keypair[]) {
      const tx: Transaction = await builder.transaction();
      tx.instructions.unshift(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }));
      tx.feePayer = signers[0].publicKey;
      const sig = await sendAndConfirmTransaction(conn, tx, signers, { commitment: "confirmed" });
      const meta = (await conn.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }))!.meta!;
      report[name] = { bytes: tx.serialize().length, compute_units: meta.computeUnitsConsumed };
    }
    // The relayer names the owner of the note its fee lands in; nobody else is asked.
    const relayerSecret = randomSecret();
    const relayerOwner = Array.from(toBytes32(ownerOf(hash, relayerSecret)));
    const withdraw = (spend: any, amount: bigint, to: PublicKey, fee = 0n) => program.methods
      .withdraw(spend, new anchor.BN(amount.toString()), new anchor.BN(fee.toString()), relayerOwner as any)
      .accounts({ payer: relayer.publicKey, market, tree: treePda, spent: spentPda(spend.nullifiers[0]), spent2: spentPda(spend.nullifiers[1]),
        vault, receiver: to } as any);
    const boundTo = (t: PublicKey, fee = 0n) => bind([Buffer.from("withdraw"), t.toBuffer(), u64le(fee)]);

    // Two deposits from the trader's wallet: the only transactions it ever signs.
    const notes: Note[] = [];
    for (const amount of [7_000n * USD, 3_000n * USD]) {
      const secret = randomSecret();
      await program.methods.deposit(Array.from(toBytes32(ownerOf(hash, secret))) as any, new anchor.BN(amount.toString()))
        .accounts({ payer: depositor.publicKey, market, tree: treePda, vault, payerToken: depositorToken } as any).signers([depositor]).rpc();
      notes.push({ secret, amount, index: await indexOfLeaf(leafOf(hash, secret, amount)) });
    }
    expect(await noteBalance()).to.equal(10_000n * USD);

    // A relayer sends a 2,500 USDC withdrawal out of the 7,000 note to a wallet that never touched the program.
    const first = await proveSpend(hash, tree, notes[0], 2_500n * USD, boundTo(receiverToken), ZK);
    await send("withdraw", withdraw(first.spend, 2_500n * USD, receiverToken), [relayer]);
    const change: Note = { secret: first.change.secret, amount: first.change.amount, index: await indexOfLeaf(first.change.leaf) };
    expect(await balOf(receiverToken)).to.equal(2_500n * USD);
    expect(change.amount).to.equal(4_500n * USD);
    expect(await noteBalance()).to.equal(7_500n * USD);

    const refused: Record<string, boolean> = {};
    const fails = async (name: string, f: () => Promise<any>, want: RegExp) => {
      try { await f(); refused[name] = false; } catch (e) {
        refused[name] = want.test(String(e) + JSON.stringify((e as any).logs ?? ""));
        if (!refused[name]) console.log(name, String(e), (e as any).logs);
      }
    };
    // The 7,000 note is spent. Its leaf is still in the tree, so a proof builds, but the nullifier is taken.
    await fails("double_spend", async () => {
      const again = await proveSpend(hash, tree, notes[0], 1n * USD, boundTo(receiverToken), ZK);
      await send("x", withdraw(again.spend, 1n * USD, receiverToken), [relayer]);
    }, /already in use/);
    // Whoever relays a withdrawal cannot point it at their own account, or raise the amount.
    const honest = await proveSpend(hash, tree, change, 1_000n * USD, boundTo(receiverToken), ZK);
    await fails("redirected", () => send("x", withdraw(honest.spend, 1_000n * USD, thiefToken), [relayer]), /BadProof/);
    await fails("raised_amount", () => send("x", withdraw(honest.spend, 1_001n * USD, receiverToken), [relayer]), /BadProof/);
    // Nor can the relayer help itself to a fee the trader did not sign off.
    await fails("added_fee", () => send("x", withdraw(honest.spend, 999n * USD, receiverToken, 1n * USD), [relayer]), /BadProof/);
    // One note cannot fill both inputs of a spend to count twice.
    await fails("same_note_twice", async () => {
      const p = await proveSpend(hash, tree, [change, change], change.amount * 2n, boundTo(thiefToken), ZK);
      await send("x", withdraw(p.spend, change.amount * 2n, thiefToken), [relayer]);
    }, /already in use/);
    // A note cannot pay more than it holds: the circuit has no such proof.
    await fails("overspend", () => proveSpend(hash, tree, change, change.amount + 1n, boundTo(receiverToken), ZK), /Assert Failed|Error in template/);
    // A proof against a tree that never existed (a made-up note) is refused before the proof is even checked.
    await fails("made_up_note", async () => {
      const fake = new NoteTree(hash);
      const secret = randomSecret();
      fake.set(0, leafOf(hash, secret, 1_000_000n * USD));
      const p = await proveSpend(hash, fake, { secret, amount: 1_000_000n * USD, index: 0 }, 1_000_000n * USD, boundTo(thiefToken), ZK);
      await send("x", withdraw(p.spend, 1_000_000n * USD, thiefToken), [relayer]);
    }, /UnknownRoot/);
    expect(refused).to.deep.equal({ double_spend: true, redirected: true, raised_amount: true, added_fee: true, same_note_twice: true,
      overspend: true, made_up_note: true });
    expect(await balOf(thiefToken)).to.equal(0n);

    // The honest proof from above still lands as built, and the rest follows: every note out, nothing left owed.
    await send("x", withdraw(honest.spend, 1_000n * USD, receiverToken), [relayer]);
    const rest: Note = { secret: honest.change.secret, amount: honest.change.amount, index: await indexOfLeaf(honest.change.leaf) };
    // The last two notes (3,500 and 3,000) leave in ONE spend, with a 0.25 USDC fee for the relayer, paid as a note.
    const FEE = 250_000n;
    const both = await proveSpend(hash, tree, [rest, notes[1]], rest.amount + notes[1].amount, boundTo(receiverToken, FEE), ZK);
    await send("merge_withdraw_with_fee", withdraw(both.spend, rest.amount + notes[1].amount - FEE, receiverToken, FEE), [relayer]);
    await indexOfLeaf(both.change.leaf);
    expect(await balOf(receiverToken)).to.equal(10_000n * USD - FEE);
    expect(await noteBalance()).to.equal(FEE);
    // The relayer cashes its fee note like anyone else.
    const feeNote: Note = { secret: relayerSecret, amount: FEE, index: await indexOfLeaf(leafOf(hash, relayerSecret, FEE)) };
    const cash = await proveSpend(hash, tree, feeNote, FEE, boundTo(relayerToken), ZK);
    await send("x", withdraw(cash.spend, FEE, relayerToken), [relayer]);
    await indexOfLeaf(cash.change.leaf);
    expect(await balOf(relayerToken)).to.equal(FEE);
    expect(await balOf(vault)).to.equal(0n);
    expect(await noteBalance()).to.equal(0n);
    delete report.x;
    report.refused = refused;
    report.leaves = (await chainTree()).nextIndex;
    fs.mkdirSync("logs", { recursive: true });
    fs.writeFileSync("logs/notes.json", JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report));
  });
});
