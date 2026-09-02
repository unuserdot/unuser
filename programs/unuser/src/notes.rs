//! Notes: the only form in which a trader's money exists on chain.
//!
//! A note is a leaf Poseidon(Poseidon(secret), amount) in one append-only tree. Depositing adds a leaf.
//! Spending proves in zero knowledge (circuits/spend.circom) that up to two leaves cover the amount, publishes
//! their nullifiers and adds a change leaf. A payout, a refund or a relayer's fee adds a leaf for an owner named
//! in advance. No instruction ever names the wallet behind a note, so there is no account to follow.
//!
//! Poseidon here is the Solana syscall with circomlib's parameters, big-endian, so hashes equal the circuit's.
// solana-poseidon 3.x flags its whole API as unstable ahead of v4; the version is pinned in Cargo.toml.
#![allow(deprecated)]
use anchor_lang::prelude::*;
use groth16_solana::groth16::Groth16Verifier;
use solana_poseidon::{hashv, Endianness, Parameters};

use crate::{vk, ErrorCode};

pub const TREE_DEPTH: usize = 20;
/// A proof may use any of the last ROOT_HISTORY roots, so a spend built a moment ago still lands after
/// other leaves were added.
pub const ROOT_HISTORY: usize = 64;

pub type Node = [u8; 32];

#[account(zero_copy)]
pub struct Tree {
    pub filled: [Node; TREE_DEPTH],
    pub zeros: [Node; TREE_DEPTH + 1],
    pub roots: [Node; ROOT_HISTORY],
    pub next_index: u32,
    pub head: u32,
}

#[event]
pub struct NoteEvent {
    pub index: u32,
    pub leaf: [u8; 32],
}

pub fn poseidon(inputs: &[&[u8]]) -> Result<Node> {
    hashv(Parameters::Bn254X5, Endianness::BigEndian, inputs)
        .map(|h| h.to_bytes())
        .map_err(|_| error!(ErrorCode::NotAFieldElement))
}

pub fn field_u64(value: u64) -> Node {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

impl Tree {
    pub fn init(&mut self) -> Result<()> {
        for i in 0..TREE_DEPTH {
            self.zeros[i + 1] = poseidon(&[&self.zeros[i], &self.zeros[i]])?;
            self.filled[i] = self.zeros[i];
        }
        self.roots[0] = self.zeros[TREE_DEPTH];
        Ok(())
    }

    pub fn knows(&self, root: &Node) -> bool {
        self.roots.iter().any(|r| r == root)
    }

    pub fn insert(&mut self, leaf: Node) -> Result<u32> {
        let index = self.next_index;
        require!((index as u64) < (1u64 << TREE_DEPTH), ErrorCode::TreeFull);
        let mut position = index;
        let mut node = leaf;
        for i in 0..TREE_DEPTH {
            node = if position & 1 == 0 {
                self.filled[i] = node;
                poseidon(&[&node, &self.zeros[i]])?
            } else {
                poseidon(&[&self.filled[i], &node])?
            };
            position >>= 1;
        }
        self.next_index = index + 1;
        self.head = (self.head + 1) % ROOT_HISTORY as u32;
        self.roots[self.head as usize] = node;
        emit!(NoteEvent { index, leaf });
        Ok(index)
    }

    /// Adds a note of `amount` for `owner` = Poseidon(secret), as in circuits/spend.circom.
    pub fn credit(&mut self, owner: &Node, amount: u64) -> Result<u32> {
        let leaf = poseidon(&[owner, &field_u64(amount)])?;
        self.insert(leaf)
    }
}

/// What a spend shows the chain. Everything else (which note, how much it held) stays with the prover.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Spend {
    /// Groth16 proof: A negated, B, C.
    pub proof: [u8; 256],
    pub root: [u8; 32],
    /// Every spend has two inputs; a spend from one note carries a random second nullifier.
    pub nullifiers: [[u8; 32]; 2],
    pub change_leaf: [u8; 32],
}

/// SHA-256 of what the spend pays for, cut to 248 bits so it is a field element: the `x` of the circuit.
pub fn bind(parts: &[&[u8]]) -> Node {
    let mut x = solana_sha256_hasher::hashv(parts).to_bytes();
    x[0] = 0;
    x
}

/// Checks the proof for `amount` bound to `x` against a root the tree still remembers, then adds the change
/// note. The caller creates the two nullifier accounts, which is what stops a second spend of the same note
/// (and the same note filling both inputs).
pub fn spend(tree: &mut Tree, s: &Spend, amount: u64, x: &Node) -> Result<()> {
    require!(tree.knows(&s.root), ErrorCode::UnknownRoot);
    let a: &[u8; 64] = s.proof[0..64].try_into().unwrap();
    let b: &[u8; 128] = s.proof[64..192].try_into().unwrap();
    let c: &[u8; 64] = s.proof[192..256].try_into().unwrap();
    // snarkjs order: outputs (nullifier[2], changeLeaf), then public inputs (root, spend, x).
    let inputs: [[u8; 32]; vk::NR_INPUTS] =
        [s.nullifiers[0], s.nullifiers[1], s.change_leaf, s.root, field_u64(amount), *x];
    Groth16Verifier::new(a, b, c, &inputs, &vk::VERIFYING_KEY)
        .and_then(|mut v| v.verify())
        .map_err(|_| error!(ErrorCode::BadProof))?;
    tree.insert(s.change_leaf)?;
    Ok(())
}

/// Spends `amount + fee`, and pays `fee` as a note to the owner the relayer named. The fee is part of `x`, so
/// the relayer cannot raise it; who collects it is the relayer's own choice and is not bound.
pub fn spend_with_fee(tree: &mut Tree, s: &Spend, amount: u64, fee: u64, relayer: &Node, x: &Node) -> Result<()> {
    let total = amount.checked_add(fee).ok_or(ErrorCode::BadProof)?;
    spend(tree, s, total, x)?;
    if fee > 0 {
        tree.credit(relayer, fee)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::__private::bytemuck::Zeroable;

    fn hex(n: &Node) -> String {
        n.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn empty_tree_matches_circomlib() {
        // circomlibjs: poseidon([0, 0])
        let mut t = Box::new(Tree::zeroed());
        t.init().unwrap();
        assert_eq!(hex(&t.zeros[1]), "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864");
        assert!(t.knows(&t.zeros[TREE_DEPTH]));
    }

    #[test]
    fn inserts_match_a_full_recomputation() {
        let mut t = Box::new(Tree::zeroed());
        t.init().unwrap();
        let mut leaves = Vec::new();
        for i in 0..37u64 {
            let leaf = poseidon(&[&field_u64(i + 1), &field_u64(1_000 * i)]).unwrap();
            assert_eq!(t.insert(leaf).unwrap(), i as u32);
            leaves.push(leaf);
            let mut level = leaves.clone();
            for zero in t.zeros.iter().take(TREE_DEPTH) {
                if level.len() % 2 == 1 {
                    level.push(*zero);
                }
                level = level.chunks(2).map(|p| poseidon(&[&p[0], &p[1]]).unwrap()).collect();
            }
            assert_eq!(t.roots[t.head as usize], level[0]);
        }
    }

    #[test]
    fn old_roots_are_forgotten_after_the_history_wraps() {
        let mut t = Box::new(Tree::zeroed());
        t.init().unwrap();
        t.insert(field_u64(1)).unwrap();
        let early = t.roots[t.head as usize];
        for i in 0..ROOT_HISTORY as u64 - 1 {
            t.insert(field_u64(2 + i)).unwrap();
        }
        assert!(t.knows(&early));
        t.insert(field_u64(999)).unwrap();
        assert!(!t.knows(&early));
    }

    #[test]
    fn bind_is_a_field_element() {
        assert_eq!(bind(&[b"withdraw", &[7u8; 32]])[0], 0);
    }
}
