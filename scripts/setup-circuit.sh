#!/usr/bin/env bash
# Compiles the spend circuit, runs a LOCAL single-party Groth16 setup (BN254) and writes the
# verifying key the program compiles in. Whoever runs this knows the toxic waste and could forge
# proofs, so this setup is for tests only: real money needs a multi-party phase 2 ceremony.
# Nothing is downloaded.
#   zk/spend_js/spend.wasm            witness generator (client)
#   zk/spend.zkey                     proving key (client)
#   zk/verification_key.json          verifying key
#   programs/unuser/src/vk.rs         the same key as Rust constants
set -euo pipefail
cd "$(dirname "$0")/.."
SNARKJS=node_modules/.bin/snarkjs
mkdir -p zk
circom circuits/spend.circom --O2 --r1cs --wasm --sym -o zk
if [ ! -f zk/pot14_final.ptau ]; then
  $SNARKJS powersoftau new bn128 14 zk/pot14_0.ptau
  $SNARKJS powersoftau contribute zk/pot14_0.ptau zk/pot14_1.ptau --name="local" -e="$(head -c 64 /dev/urandom | base64)"
  $SNARKJS powersoftau prepare phase2 zk/pot14_1.ptau zk/pot14_final.ptau
  rm zk/pot14_0.ptau zk/pot14_1.ptau
fi
$SNARKJS groth16 setup zk/spend.r1cs zk/pot14_final.ptau zk/spend_0.zkey
$SNARKJS zkey contribute zk/spend_0.zkey zk/spend.zkey --name="local" -e="$(head -c 64 /dev/urandom | base64)"
rm zk/spend_0.zkey
$SNARKJS zkey export verificationkey zk/spend.zkey zk/verification_key.json
node tools/groth16-bytes.js zk/verification_key.json > programs/unuser/src/vk.rs
$SNARKJS r1cs info zk/spend.r1cs
