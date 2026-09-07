pragma circom 2.1.9;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// One spend: "up to two notes in the tree hold at least `spend` between them; here are their
// nullifiers, and here is the note that carries what is left".
//
// A note is a leaf Poseidon(Poseidon(secret), amount). Whoever knows `secret` can spend it once.
// Spending publishes the nullifier Poseidon(secret, 1), which says nothing about which leaf it was,
// and a change leaf for the remainder under a fresh secret. The change leaf is always produced,
// even for zero, so a full spend and a partial spend look the same.
//
// Every spend takes two inputs, so merging two notes looks like any other spend. A spend from one
// note fills the second input with a note of amount zero and a random secret: an input of zero need
// not be in the tree, and its nullifier is a random number.
//
// `x` binds the proof to what it pays for (an order, a withdrawal address, the relayer's fee): the
// program recomputes it from the instruction, so nobody who relays the proof can change any of it.
template Spend(DEPTH) {
    // Public inputs
    signal input root;
    signal input spend;
    signal input x;

    // Private inputs
    signal input secret[2];
    signal input amount[2];
    signal input pathElements[2][DEPTH];
    signal input pathIndices[2][DEPTH];
    signal input changeSecret;

    signal output nullifier[2];
    signal output changeLeaf;

    component owner[2];
    component leaf[2];
    component levels[2][DEPTH];
    component order[2][DEPTH];
    component amountBits[2];
    component spent[2];
    signal node[2][DEPTH + 1];

    for (var n = 0; n < 2; n++) {
        owner[n] = Poseidon(1);
        owner[n].inputs[0] <== secret[n];
        leaf[n] = Poseidon(2);
        leaf[n].inputs[0] <== owner[n].out;
        leaf[n].inputs[1] <== amount[n];

        node[n][0] <== leaf[n].out;
        for (var i = 0; i < DEPTH; i++) {
            pathIndices[n][i] * (pathIndices[n][i] - 1) === 0;
            order[n][i] = MultiMux1(2);
            order[n][i].c[0][0] <== node[n][i];
            order[n][i].c[0][1] <== pathElements[n][i];
            order[n][i].c[1][0] <== pathElements[n][i];
            order[n][i].c[1][1] <== node[n][i];
            order[n][i].s <== pathIndices[n][i];
            levels[n][i] = Poseidon(2);
            levels[n][i].inputs[0] <== order[n][i].out[0];
            levels[n][i].inputs[1] <== order[n][i].out[1];
            node[n][i + 1] <== levels[n][i].out;
        }
        // A note that holds anything must be in the tree under `root`.
        (node[n][DEPTH] - root) * amount[n] === 0;

        amountBits[n] = Num2Bits(64);
        amountBits[n].in <== amount[n];

        spent[n] = Poseidon(2);
        spent[n].inputs[0] <== secret[n];
        spent[n].inputs[1] <== 1;
        nullifier[n] <== spent[n].out;
    }

    // spend <= amount[0] + amount[1], and what is left is again a 64-bit token amount.
    component spendBits = Num2Bits(64);
    spendBits.in <== spend;
    component covered = LessEqThan(65);
    covered.in[0] <== spend;
    covered.in[1] <== amount[0] + amount[1];
    covered.out === 1;
    component leftBits = Num2Bits(64);
    leftBits.in <== amount[0] + amount[1] - spend;

    component changeOwner = Poseidon(1);
    changeOwner.inputs[0] <== changeSecret;
    component change = Poseidon(2);
    change.inputs[0] <== changeOwner.out;
    change.inputs[1] <== amount[0] + amount[1] - spend;
    changeLeaf <== change.out;

    // Ties `x` into the proof; without a constraint it could be swapped freely.
    signal bound;
    bound <== x * x;
}

component main {public [root, spend, x]} = Spend(20);
