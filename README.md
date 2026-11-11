![UNUSER](docs/banner.png)

# UNUSER

SOL perpetuals with no user accounts.

A wallet pays USDC into the vault once and gets a note. From then on every order, close and withdrawal is
paid from notes with a zero-knowledge proof and sent by anyone, so the chain can see that somebody traded
and cannot see who. The order itself (side, size, leverage, liquidation price) is sealed for an MPC cluster,
so the chain cannot see what was traded either.

## How it works

**Notes hide who.** A note is a leaf `Poseidon(Poseidon(secret), amount)` in one append-only Merkle tree.
Spending proves, with a Groth16 proof checked on chain, that up to two leaves in the tree cover the amount.
The proof publishes their nullifiers (so they cannot be spent twice) and a change leaf for what is left.
Nothing in the transaction says which leaves were spent or how much they held. Every spend has two inputs,
so merging two notes looks like any other spend.

**Refunds are notes too.** When a position opens, the trader names the owner of a future note. A payout at
close, or the refund of a rejected order, becomes a new leaf for that owner. Money never returns to a wallet
until the trader withdraws it, to any address, with the same kind of proof.

**MPC hides what.** Size and side are encrypted in the browser for an [Arcium](https://arcium.com) cluster.
The cluster checks the leverage cap, keeps one sealed liquidation line per position, marks positions to
liquidate at the oracle price, and at close reveals one number: the payout.

**Nobody in the middle can cheat.** Each proof is bound to a hash of everything it pays for (the sealed
order, the one-time key that may close it, the note owner the money returns to, the receiving account of a
withdrawal, the relayer's fee). A relayer that changes any of it makes the proof invalid.

**Relayers are paid in notes.** The trader sets a fee inside the proof; whoever sends the transaction names
the note owner that collects it. A close pays its relayer out of the payout the same way. A relayer needs no
account either.

The note design follows the credit-with-refund pattern of anonymous usage credits (Buterin and Crapis,
"ZK API Usage Credits", and the IETF Anonymous Credit Tokens draft): spend from a private balance, get the
remainder back as a fresh private balance. Here the service being paid for is a trading position.

## What the chain sees

| Public | Hidden |
|---|---|
| a wallet deposited an amount | which note pays for which position |
| a position opened in a slot, its collateral, the time | the balance left in any note |
| a position was liquidated, after the fact | side, size, leverage, liquidation price |
| the payout of a closed position | which wallet the payout belongs to |
| an amount was withdrawn to an address | which deposit it came from |

## Layout

- `circuits/spend.circom`: the spend proof (11,877 constraints, 3 public inputs, 3 public outputs).
- `programs/unuser/src/notes.rs`: the note tree, the on-chain proof check, the binding hash.
- `programs/unuser/src/lib.rs`: market, LP pool, deposit and withdraw, open, check, liquidate, close.
- `encrypted-ixs/src/lib.rs`: the three MPC circuits (`open_pos`, `chk128`, `close_pnl`).
- `sdk/notes.ts`: client side of a note (tree mirror, proving).
- `tests/circuit.ts`: the circuit alone, no chain.
- `tests/notes.ts`: the note layer on a plain local validator.
- `tests/engine.ts`: the whole exchange on a local Arcium cluster.

## Build and test

Needs Rust, the Solana CLI, Anchor 1.0, the Arcium CLI 0.15, circom 2.2, Node 24 and Docker.

```bash
yarn install
bash scripts/setup-circuit.sh   # compiles the circuit, local Groth16 setup, writes programs/unuser/src/vk.rs
arcium build
yarn test:circuit               # the circuit alone
yarn test:notes                 # host tests, then the note layer on its own local chain
arcium test                     # the whole exchange on a local Arcium cluster
```

## Status

Research code, local only. Nothing is deployed.

Measured on a local validator (`tests/notes.ts`, which writes `logs/notes.json`):

| | result |
|---|---|
| withdrawal with a proof, sent by a relayer | 915 bytes, 165,681 compute units |
| two notes spent in one withdrawal, with a relayer fee paid as a note | 915 bytes, 183,232 compute units |
| spending a note twice, or one note in both inputs | refused (the nullifier account already exists) |
| relayer redirects a withdrawal, raises its amount, or adds a fee | refused (`BadProof`) |
| spending more than the notes hold | no proof exists |
| a proof for a note that was never in the tree | refused (`UnknownRoot`) |
| deposits 10,000 USDC | 9,999.75 to the receiver, 0.25 to the relayer, vault 0, nothing owed to notes |

Measured on a local Arcium cluster, two nodes (`tests/engine.ts`, which writes `logs/gate1.json`):

| | result |
|---|---|
| two deposits (40,000 and 1,500 USDC), then six sealed positions paid from one note and its change | 6 of 6 opened, about 4.5 s each, proof built in about 1 s |
| open sent by a relayer | 1,070 bytes, 184,596 compute units |
| reused note, swapped close key, raised relayer fee, redirected withdrawal, overspend, close by a stranger | all refused |
| an order over the 10x cap | rejected inside MPC, refunded as a 1,001 USDC note |
| price 150 to 128, one check round | 3.8 s, marked slots 2 and 4, exactly the plain-text answer |
| the other four close at 145 | every payout equal to the plain-text formula to the micro-USDC, about 3.9 s each |
| the trader's notes withdrawn two at a time to a fresh wallet | 40,842.972985 USDC, exactly deposits minus position costs and relayer fees plus payouts |
| the relayer | paid 0.75 USDC in 15 notes of 0.05, cashed two at a time |
| books | nothing owed to notes, vault equals the pool, vault 0 after the LP leaves |
| 24 trading transactions scanned | 0 name the depositing wallet or its token account, 0 signed by anything but the relayer and one-time close keys |

## Limits

- **Local trusted setup.** `scripts/setup-circuit.sh` runs a one-party setup, so whoever ran it could forge
  proofs. Real money needs a multi-party ceremony.
- **Amounts and timing still talk.** Deposit, collateral, payout and withdrawal amounts are public. A lone
  user, or one who deposits and withdraws a distinctive amount, can be matched by eye. Privacy grows with the
  number of notes in the tree.
- **Two notes per spend.** A trader with many small notes merges them two at a time.
- **A relayer sees the sender's IP address**, and a refund of a rejected order pays its relayer nothing.
- **No keeper yet.** Fills, check rounds and liquidations are sent by the test; a service that does it on its
  own is not in this repository.
- **The cluster must answer.** Liquidation checks and closes wait on the MPC cluster. An outage delays them,
  which caps safe leverage.
- **Not audited.**

## License

MIT
