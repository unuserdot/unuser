use arcis::*;

// UNUSER engine circuits.
// Units: size in 1e-9 SOL, entry price and collateral in 1e-6 USD, thresholds and check prices in 1e-4 USD.
//
// Book slots are encrypted to one fixed "book key": an x25519 public key hashed from a public string
// (8 x the point sha256("UNUSER book key v1 #0"), see tools/book_key.py), so nobody holds its private key and only the cluster
// can decrypt a slot, as with Enc<Mxe>. Unlike Enc<Mxe>, the nonce can then travel apart from the
// ciphertexts, so one check round reads 128 slots from one contiguous account range plus 128 nonces.
// (Each slot has to be encrypted on its own: an Arcium answer must fit one Solana transaction, so an open
// cannot rewrite a whole encrypted book. An account argument that spans nonces is refused by Arcium with
// InvalidArguments, and one account argument per slot does not fit the 10 KB CPI limit at 256 slots.)
#[encrypted]
mod circuits {
    use arcis::*;

    const SIZE_SCALE: u128 = 1_000_000_000;

    // One book slot: the single number a liquidation check needs, plus the side.
    //   long : liquidate when price <= v
    //   short: liquidate when price >  v
    #[derive(Copy, Clone)]
    pub struct Lim32 {
        v: u32,
        long: bool,
    }

    // What the trader sends with an open request. The fill price is not known yet (the position fills at the first
    // oracle update after the request, so a trader who sees the market move first cannot pick a stale price), so
    // the trader cannot work out the liquidation threshold. Instead they send w = floor(coll * 1e9 / size), the
    // collateral per unit of size, which the circuit checks with multiplications; the threshold is then derived
    // here from the fill price. The side rides in bit 40 of w (w + 2^40 for a long): two ciphertexts per open.
    #[derive(Copy, Clone)]
    pub struct PosIn {
        size: u64,
        w: u64,
    }

    const LONG_BIT: u64 = 1_099_511_627_776; // 2^40

    // What close needs later. Entry price and collateral are public on the position account.
    #[derive(Copy, Clone)]
    pub struct PosRec {
        size: u64,
        long: bool,
    }

    // Open, at the fill price `entry`: checks w against the collateral and the leverage cap, derives the
    // liquidation threshold for the 2.5% maintenance margin, and returns the book slot (encrypted to the book key),
    // the close record (encrypted for the cluster) and one public bit, whether the position obeyed the rules.
    // With base = 1e4 * coll * 1e9 >= 1e4 * w * size (w is a floor), the thresholds in 1e-4 USD are
    //   long : floor(1e4 * (entry - w) / 975000)          liquidate when price <= v
    //   short: floor((1e4 * (entry + w) - 1) / 1025000)    liquidate when price >  v
    // which never sit beyond the exact thresholds (the floor on w only moves the line toward safety).
    #[instruction]
    pub fn open_pos(
        pos: Enc<Shared, PosIn>,
        entry: u64,
        coll: u64,
        max_lev: u64,
        book_key: ArcisX25519Pubkey,
    ) -> (Enc<Shared, Lim32>, Enc<Mxe, PosRec>, bool) {
        let p = pos.to_arcis();
        let long = p.w >= LONG_BIT;
        let w = (if long { p.w - LONG_BIT } else { p.w }) as u128;
        let size = p.size as u128;
        let cs = (coll as u128) * SIZE_SCALE;
        let e = entry as u128;
        let w_ok = w * size <= cs && cs < (w + 1) * size;
        let lev_ok = size * e <= (max_lev as u128) * cs;
        let ok = w_ok && lev_ok && p.size > 0;
        let v_long = if e > w { (10_000 * (e - w)) / 975_000 } else { 0 };
        let v_short = (10_000 * (e + w) - 1) / 1_025_000;
        let v = if long { v_long } else { v_short };
        let lim = Lim32 { v: v as u32, long };
        let rec = PosRec { size: p.size, long };
        (Shared::new(book_key).from_arcis(lim), Mxe::get().from_arcis(rec), ok.reveal())
    }

    // Check: 128 slots, each with its own nonce under the book key. Reveals one bit per slot (1 = liquidate).
    // 256 slots (5.73 B ACUs) is refused by Arcium as too large (InvalidCUAmount); 128 is 3.06 B.
    #[instruction]
    pub fn chk128(key: ArcisX25519Pubkey, nonces: [u128; 128], data: [EncData<Lim32>; 128], price: u64) -> [u64; 2] {
        let px = price as u32;
        let mut out = [0u64; 2];
        for i in 0..128 {
            let s = data[i].clone().to_arcis_with_pubkey_and_nonce(key, nonces[i]);
            if (px <= s.v) == s.long {
                out[i / 64] += 1u64 << (i % 64);
            }
        }
        out.reveal()
    }

    // Close: the only thing revealed is the payout. Entry and exit prices are public; size and side stay
    // hidden. Nothing secret is ever divided (division is very deep in MPC): the payout comes out scaled by
    // 1e13 (units of 1e-19 USD) and the program divides it in the open.
    //   value = coll * 1e13 + gain - loss - fees, floored at 0
    //   gain or loss = 1e4 * size * |exit - entry|, a gain when the side matches the move
    //   fees = size * ((entry + exit) * fee_bps + entry * borrow_bps), borrow_bps = rate per hour * hours
    #[instruction]
    pub fn close_pnl(
        rec: Enc<Mxe, PosRec>,
        entry: u64,
        exit: u64,
        coll: u64,
        fee_bps: u64,
        borrow_bps: u64,
    ) -> u128 {
        let r = rec.to_arcis();
        let size = r.size as u128;
        let up = exit >= entry;
        let diff = (if up { exit - entry } else { entry - exit }) as u128;
        let mag = 10_000u128 * size * diff;
        let win = r.long == up;
        let fees = size * ((entry as u128 + exit as u128) * (fee_bps as u128) + (entry as u128) * (borrow_bps as u128));
        let plus = (coll as u128) * 10_000_000_000_000u128 + if win { mag } else { 0 };
        let minus = fees + if win { 0 } else { mag };
        let v = if plus > minus { plus - minus } else { 0 };
        v.reveal()
    }
}
