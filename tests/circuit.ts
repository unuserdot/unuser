// The spend circuit alone, no chain: a proof for an honest spend verifies, a changed public value does not, and
// the circuit has no proof for spending more than the notes hold or for a note that is not in the tree.
// Run with `yarn test:circuit` after scripts/setup-circuit.sh.
import { expect } from "chai";
import * as fs from "fs";
import { Note, NoteTree, leafOf, loadHash, proveSpend, randomSecret, releaseProver } from "../sdk/notes";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");

const ZK = { wasm: "zk/spend_js/spend.wasm", zkey: "zk/spend.zkey" };

describe("spend circuit", () => {
  after(releaseProver);

  it("proves honest spends and nothing else", async () => {
    const hash = await loadHash();
    const vkey = JSON.parse(fs.readFileSync("zk/verification_key.json", "utf8"));
    const tree = new NoteTree(hash);
    const notes: Note[] = [700n, 300n].map((amount, index) => {
      const secret = randomSecret();
      tree.set(index, leafOf(hash, secret, amount));
      return { secret, amount, index };
    });
    // snarkjs wants the proof object, so prove here with the same inputs the SDK builds.
    const prove = async (from: Note | [Note, Note], amount: bigint) => {
      const list = Array.isArray(from) ? from : [from, { secret: randomSecret(), amount: 0n, index: 0 }];
      const paths = list.map((n) => tree.path(n.index));
      return snarkjs.groth16.fullProve({
        root: tree.root().toString(), spend: amount.toString(), x: "42",
        secret: list.map((n) => n.secret.toString()), amount: list.map((n) => n.amount.toString()),
        pathElements: paths.map((p) => p.pathElements.map(String)), pathIndices: paths.map((p) => p.pathIndices),
        changeSecret: randomSecret().toString(),
      }, ZK.wasm, ZK.zkey);
    };

    // One note, partly spent; two notes merged and fully spent.
    for (const [from, amount] of [[notes[0], 250n], [[notes[0], notes[1]], 1000n]] as [Note | [Note, Note], bigint][]) {
      const { proof, publicSignals } = await prove(from, amount);
      expect(await snarkjs.groth16.verify(vkey, publicSignals, proof)).to.equal(true);
      // Public signals: nullifier[2], changeLeaf, root, spend, x. Changing any of them breaks the proof.
      for (let i = 0; i < publicSignals.length; i++) {
        const bad = [...publicSignals];
        bad[i] = (BigInt(bad[i]) + 1n).toString();
        expect(await snarkjs.groth16.verify(vkey, bad, proof)).to.equal(false);
      }
    }
    // The SDK's change note is what the circuit committed to.
    const viaSdk = await proveSpend(hash, tree, notes[0], 250n, 42n, ZK);
    expect(viaSdk.change.leaf).to.equal(leafOf(hash, viaSdk.change.secret, 450n));

    const noProof = async (f: () => Promise<any>) => { try { await f(); return false; } catch { return true; } };
    expect(await noProof(() => prove(notes[0], 701n))).to.equal(true); // more than the note holds
    expect(await noProof(() => prove([notes[0], notes[1]], 1001n))).to.equal(true); // more than both hold
    expect(await noProof(() => prove({ secret: randomSecret(), amount: 500n, index: 1 }, 1n))).to.equal(true); // not in the tree
  });
});
