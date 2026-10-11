#!/usr/bin/env bash
# The note layer on its own validator: host tests for the tree, then tests/notes.ts against a fresh local chain
# that holds only this program. Ports are set apart so it runs beside any other local stack.
# Needs `arcium build` (or `anchor build`) and scripts/setup-circuit.sh first.
set -euo pipefail
cd "$(dirname "$0")/.."
# mocha 9 needs Node 24 or older (Node 26 refuses its yargs entry file); use it when Homebrew has it.
[ -d /opt/homebrew/opt/node@24/bin ] && export PATH="/opt/homebrew/opt/node@24/bin:$PATH"
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
RPC_PORT=${RPC_PORT:-18899}
LEDGER=target/notes-ledger
WALLET=target/notes-wallet.json
PROGRAM=$(solana-keygen pubkey target/deploy/unuser-keypair.json)

cargo test -p unuser --lib

[ -f "$WALLET" ] || solana-keygen new --no-bip39-passphrase -s -o "$WALLET" >/dev/null
rm -rf "$LEDGER"
solana-test-validator --ledger "$LEDGER" --rpc-port "$RPC_PORT" --faucet-port $((RPC_PORT + 5)) \
  --gossip-port $((RPC_PORT + 6)) --dynamic-port-range $((RPC_PORT + 10))-$((RPC_PORT + 40)) \
  --mint "$(solana-keygen pubkey "$WALLET")" --bpf-program "$PROGRAM" target/deploy/unuser.so --quiet > target/notes-validator.log 2>&1 &
VALIDATOR=$!
trap 'kill $VALIDATOR 2>/dev/null || true' EXIT
for _ in $(seq 60); do solana cluster-version -u "http://127.0.0.1:$RPC_PORT" >/dev/null 2>&1 && break; sleep 0.5; done

ANCHOR_PROVIDER_URL="http://127.0.0.1:$RPC_PORT" ANCHOR_WALLET="$WALLET" \
  yarn run ts-mocha -p ./tsconfig.json -t 600000 --exit tests/notes.ts
