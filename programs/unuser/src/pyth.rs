//! Reads Pyth's SOL/USD price from the receiver program's PriceUpdateV2 account by hand, so the program needs no
//! Pyth crate (its SDK pins an older Anchor than ours). The account is Borsh: an 8 byte discriminator, the 32 byte
//! write authority, the verification level (tag 1 = Full, or tag 0 = Partial followed by a signature count), then
//! the price message: feed id 32, price i64, conf u64, exponent i32, publish time i64, previous publish time i64,
//! EMA price i64, EMA conf u64, and finally the posted slot u64.
//!
//! This file has no dependencies so it can be tested on its own:
//! `rustc --edition 2021 --test programs/unuser/src/pyth.rs -o /tmp/pyth_test && /tmp/pyth_test`

/// sha256("account:PriceUpdateV2")[..8]
pub const DISCRIMINATOR: [u8; 8] = [34, 241, 35, 99, 157, 126, 244, 205];
/// The SOL/USD feed id, ef0d8b6f...280b56d.
pub const SOL_USD_FEED: [u8; 32] = [
    239, 13, 139, 111, 218, 44, 235, 164, 29, 161, 93, 64, 149, 209, 218, 57, 42, 13, 47, 142, 208, 198, 199, 188, 15,
    76, 250, 200, 194, 128, 181, 109,
];
/// Pyth's receiver program, rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ, which owns every PriceUpdateV2.
pub const RECEIVER: [u8; 32] = [
    12, 183, 250, 187, 82, 247, 166, 72, 187, 91, 49, 125, 154, 1, 139, 144, 87, 203, 2, 71, 116, 250, 254, 1, 230,
    196, 223, 152, 204, 56, 88, 129,
];

#[derive(Debug, PartialEq)]
pub enum PythError {
    /// Too short, wrong discriminator, or an exponent outside -18..=0.
    Layout,
    /// Only a Full Wormhole verification is accepted.
    NotFull,
    WrongFeed,
    /// Zero or negative price.
    BadPrice,
    Stale,
    /// The confidence band is wider than allowed.
    WideConf,
}

/// The price in 1e-6 USD and its publish time, checked for feed, verification, age (`now - publish_time <= max_age`)
/// and confidence (`conf <= price * max_conf_bps / 10_000`).
pub fn sol_price_e6(data: &[u8], now: i64, max_age: i64, max_conf_bps: u64) -> Result<(u64, i64), PythError> {
    if data.len() < 41 || data[..8] != DISCRIMINATOR {
        return Err(PythError::Layout);
    }
    let at = match data[40] {
        1 => 41,
        0 => return Err(PythError::NotFull),
        _ => return Err(PythError::Layout),
    };
    if data.len() < at + 32 + 8 + 8 + 4 + 8 {
        return Err(PythError::Layout);
    }
    if data[at..at + 32] != SOL_USD_FEED {
        return Err(PythError::WrongFeed);
    }
    let rd8 = |o: usize| <[u8; 8]>::try_from(&data[o..o + 8]).unwrap();
    let price = i64::from_le_bytes(rd8(at + 32));
    let conf = u64::from_le_bytes(rd8(at + 40));
    let expo = i32::from_le_bytes(<[u8; 4]>::try_from(&data[at + 48..at + 52]).unwrap());
    let publish_time = i64::from_le_bytes(rd8(at + 52));
    if price <= 0 {
        return Err(PythError::BadPrice);
    }
    if !(-18..=0).contains(&expo) {
        return Err(PythError::Layout);
    }
    if now.saturating_sub(publish_time) > max_age {
        return Err(PythError::Stale);
    }
    let price = price as u64;
    if conf as u128 * 10_000 > price as u128 * max_conf_bps as u128 {
        return Err(PythError::WideConf);
    }
    // 10^expo USD per unit, and we want units of 10^-6 USD.
    let shift = expo + 6;
    let v = if shift >= 0 {
        (price as u128) * 10u128.pow(shift as u32)
    } else {
        (price as u128) / 10u128.pow((-shift) as u32)
    };
    Ok((u64::try_from(v).map_err(|_| PythError::BadPrice)?, publish_time))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from mainnet on 2026-11-07: price 8991561962e-8, conf 3938038e-8, published at 1794044062 or
    // close to it (the file holds whatever was live at capture time; the tests read its own publish time).
    const REAL: &[u8] = include_bytes!("pyth_fixture_mainnet.bin");

    fn publish_time(d: &[u8]) -> i64 {
        i64::from_le_bytes(d[41 + 52..41 + 60].try_into().unwrap())
    }

    #[test]
    fn reads_the_real_account() {
        let t = publish_time(REAL);
        let (p, published) = sol_price_e6(REAL, t + 5, 30, 100).unwrap();
        assert_eq!(published, t);
        let raw = i64::from_le_bytes(REAL[41 + 32..41 + 40].try_into().unwrap());
        assert_eq!(p, raw as u64 / 100);
        assert!(p > 10_000_000 && p < 10_000_000_000, "SOL between $10 and $10,000: {p}");
    }

    #[test]
    fn stale_is_refused_at_the_edge() {
        let t = publish_time(REAL);
        assert!(sol_price_e6(REAL, t + 30, 30, 100).is_ok());
        assert_eq!(sol_price_e6(REAL, t + 31, 30, 100), Err(PythError::Stale));
    }

    #[test]
    fn wide_confidence_is_refused() {
        let t = publish_time(REAL);
        assert_eq!(sol_price_e6(REAL, t, 30, 0), Err(PythError::WideConf));
    }

    #[test]
    fn partial_verification_is_refused() {
        // A Partial account carries one more byte (the signature count) before the message.
        let mut d = REAL[..40].to_vec();
        d.extend_from_slice(&[0, 5]);
        d.extend_from_slice(&REAL[41..]);
        assert_eq!(sol_price_e6(&d, publish_time(REAL), 30, 100), Err(PythError::NotFull));
    }

    #[test]
    fn other_feed_and_junk_are_refused() {
        let t = publish_time(REAL);
        let mut d = REAL.to_vec();
        d[41] ^= 1;
        assert_eq!(sol_price_e6(&d, t, 30, 100), Err(PythError::WrongFeed));
        let mut d = REAL.to_vec();
        d[0] ^= 1;
        assert_eq!(sol_price_e6(&d, t, 30, 100), Err(PythError::Layout));
        assert_eq!(sol_price_e6(&REAL[..60], t, 30, 100), Err(PythError::Layout));
        let mut d = REAL.to_vec();
        d[41 + 32..41 + 40].copy_from_slice(&(-5i64).to_le_bytes());
        assert_eq!(sol_price_e6(&d, t, 30, 100), Err(PythError::BadPrice));
    }
}
