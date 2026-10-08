// Client side of a note: secrets, the mirror of the on-chain tree, and the proof that spends a note.
// A note is Poseidon(Poseidon(secret), amount); see circuits/spend.circom and programs/unuser/src/notes.rs.
import { createHash, randomBytes } from "crypto";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildPoseidon } = require("circomlibjs");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { proofBytes } = require("../tools/groth16-bytes.js");

export const DEPTH = 20;
export type Hash = (inputs: bigint[]) => bigint;

export async function loadHash(): Promise<Hash> {
  const poseidon = await buildPoseidon();
  return (inputs) => poseidon.F.toObject(poseidon(inputs)) as bigint;
}

export const toBytes32 = (v: bigint): Buffer => Buffer.from(v.toString(16).padStart(64, "0"), "hex");
export const fromBytes = (b: Uint8Array | number[]): bigint => BigInt("0x" + Buffer.from(b).toString("hex"));

/** A fresh secret: 31 random bytes, so it is always below the field modulus. */
export const randomSecret = (): bigint => fromBytes(randomBytes(31)) || 1n;

/** The `x` a spend is bound to: SHA-256 of what it pays for, cut to 248 bits (notes::bind in the program). */
export function bind(parts: (Uint8Array | Buffer)[]): bigint {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  const x = h.digest();
  x[0] = 0;
  return fromBytes(x);
}

/** A note its holder can spend: the secret, the amount and where its leaf sits in the tree. */
export interface Note {
  secret: bigint;
  amount: bigint;
  index: number;
}

/** Mirror of the on-chain note tree, filled from NoteEvents (index, leaf). */
export class NoteTree {
  readonly zeros: bigint[] = [0n];
  private readonly levels: Map<number, bigint>[];
  size = 0;

  constructor(private readonly hash: Hash) {
    for (let i = 0; i < DEPTH; i++) this.zeros.push(hash([this.zeros[i], this.zeros[i]]));
    this.levels = Array.from({ length: DEPTH + 1 }, () => new Map<number, bigint>());
  }

  set(index: number, leaf: bigint): void {
    let position = index;
    let node = leaf;
    for (let i = 0; i <= DEPTH; i++) {
      this.levels[i].set(position, node);
      if (i === DEPTH) break;
      const left = position % 2 === 0 ? node : this.node(i, position - 1);
      const right = position % 2 === 0 ? this.node(i, position + 1) : node;
      node = this.hash([left, right]);
      position = Math.floor(position / 2);
    }
    this.size = Math.max(this.size, index + 1);
  }

  node(level: number, position: number): bigint {
    return this.levels[level].get(position) ?? this.zeros[level];
  }

  root(): bigint {
    return this.node(DEPTH, 0);
  }

  indexOf(leaf: bigint): number {
    for (const [i, l] of this.levels[0]) if (l === leaf) return i;
    return -1;
  }

  path(index: number): { pathElements: bigint[]; pathIndices: number[] } {
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let position = index;
    for (let i = 0; i < DEPTH; i++) {
      pathElements.push(this.node(i, position ^ 1));
      pathIndices.push(position & 1);
      position = Math.floor(position / 2);
    }
    return { pathElements, pathIndices };
  }
}

export const ownerOf = (hash: Hash, secret: bigint): bigint => hash([secret]);
export const leafOf = (hash: Hash, secret: bigint, amount: bigint): bigint => hash([ownerOf(hash, secret), amount]);
export const nullifierOf = (hash: Hash, secret: bigint): bigint => hash([secret, 1n]);

export interface SpendArgs {
  proof: number[];
  root: number[];
  nullifiers: number[][];
  changeLeaf: number[];
}

export interface Artifacts {
  wasm: string;
  zkey: string;
}

/**
 * Proves that one or two notes cover `amount`, bound to `x`. Returns the instruction argument and the change
 * note's secret and amount; its index is known once the program has added the leaf. With one note the second
 * input is a note of zero under a random secret, which the circuit accepts without a place in the tree.
 */
export async function proveSpend(
  hash: Hash, tree: NoteTree, from: Note | [Note, Note], amount: bigint, x: bigint, artifacts: Artifacts,
): Promise<{ spend: SpendArgs; change: { secret: bigint; amount: bigint; leaf: bigint } }> {
  const notes = Array.isArray(from) ? from : [from, { secret: randomSecret(), amount: 0n, index: 0 }];
  const changeSecret = randomSecret();
  const paths = notes.map((n) => tree.path(n.index));
  const input = {
    root: tree.root().toString(),
    spend: amount.toString(),
    x: x.toString(),
    secret: notes.map((n) => n.secret.toString()),
    amount: notes.map((n) => n.amount.toString()),
    pathElements: paths.map((p) => p.pathElements.map(String)),
    pathIndices: paths.map((p) => p.pathIndices),
    changeSecret: changeSecret.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, artifacts.wasm, artifacts.zkey);
  // snarkjs order: outputs (nullifier[2], changeLeaf), then public inputs (root, spend, x).
  const [n0, n1, changeLeaf, root] = publicSignals.map((s: string) => BigInt(s));
  return {
    spend: {
      proof: Array.from(proofBytes(proof) as Buffer),
      root: Array.from(toBytes32(root)),
      nullifiers: [Array.from(toBytes32(n0)), Array.from(toBytes32(n1))],
      changeLeaf: Array.from(toBytes32(changeLeaf)),
    },
    change: { secret: changeSecret, amount: notes[0].amount + notes[1].amount - amount, leaf: changeLeaf },
  };
}

/** The eight bytes a fee adds to a binding hash (u64, little-endian), as the program hashes it. */
export function u64le(v: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v);
  return b;
}

/** snarkjs keeps BN254 worker threads alive; call once when a Node process is done proving. */
export async function releaseProver(): Promise<void> {
  const curve = (globalThis as any).curve_bn128;
  if (curve) await curve.terminate();
}
