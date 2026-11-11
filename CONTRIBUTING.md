# Contributing

Issues and pull requests are welcome.

- Build and run the tests as described in the README before opening a pull request. `yarn test:circuit` and
  `yarn test:notes` run without an Arcium cluster; `arcium test` needs Docker.
- If you change `circuits/spend.circom`, run `scripts/setup-circuit.sh` again and commit the new
  `programs/unuser/src/vk.rs`. The public signal order (nullifier[2], changeLeaf, root, spend, x) is read by
  `programs/unuser/src/notes.rs` and `sdk/notes.ts`; keep the three in step.
- Anything a proof pays for must go into the binding hash (`notes::bind`), or a relayer can change it.
- Keep changes small and say in the description what you measured.
