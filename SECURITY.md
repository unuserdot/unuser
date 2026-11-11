# Security

UNUSER is research code. It has not been audited and is not deployed to any network. Do not put money in it.

## Reporting a problem

Please report anything that could lose funds or break privacy through GitHub's private vulnerability
reporting on this repository (Security tab, "Report a vulnerability"), not in a public issue. Say what you
found, how to reproduce it, and what it lets an attacker do.

## What is known

- The Groth16 setup in `scripts/setup-circuit.sh` is run by one party, so whoever ran it can forge proofs.
  A deployment needs a multi-party ceremony and a new verifying key.
- Amounts are public (deposits, collateral, payouts, withdrawals), so privacy depends on how many notes are in
  the tree and on users not moving distinctive amounts.
- Liquidation checks and closes wait on the MPC cluster. If it stops answering, they wait too.
- `@arcium-hq/client`, used by the tests, is licensed under GPL-3.0.
