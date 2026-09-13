// UNUSER engine: SOL perpetuals with no user accounts.
// Side, size, leverage and liquidation price are held by Arcium MPC, and the money behind a position is a note
// in a zero-knowledge tree (notes.rs), so the chain sees that someone traded and never who. Collateral is USDC
// in one vault; an LP pool is every trader's counterparty. Why the book looks like this is written at the top
// of encrypted-ixs/src/lib.rs and in ENGINE.md.
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use notes::{Spend, Tree};
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::{CallbackAccount, CircuitSource};
#[cfg(not(feature = "onchain-circuits"))]
use arcium_client::idl::arcium::types::OffChainCircuitSource;
use arcium_macros::circuit_hash;

#[cfg_attr(feature = "test-oracle", allow(dead_code))]
mod pyth;
pub mod notes;
mod vk;

const COMP_DEF_OFFSET_OPEN_POS: u32 = comp_def_offset("open_pos");
const COMP_DEF_OFFSET_CHK128: u32 = comp_def_offset("chk128");
const COMP_DEF_OFFSET_CLOSE_PNL: u32 = comp_def_offset("close_pnl");
pub const SLOTS: usize = 128;
// The ciphertexts start after the discriminator, the occupancy bits and the nonces (see Book).
pub const BOOK_CTS_AT: u32 = 8 + SLOTS as u32 / 8 + SLOTS as u32 * 16;
// The highest leverage a market may allow; each market sets its own cap at or below it (`max_leverage`).
pub const MAX_LEVERAGE: u64 = 10;
// Payouts come out of close_pnl scaled by 1e13 (units of 1e-19 USD).
pub const PAYOUT_SCALE: u128 = 10_000_000_000_000;
// The market sets how old a price may be (30 s on mainnet, where Pyth's SOL account updates every 10 s), up to
// this cap. A price whose confidence band is wider than MAX_CONF_BPS of the price is refused.
pub const MAX_PRICE_AGE_CAP: u16 = 600;
pub const MAX_CONF_BPS: u64 = 100;
// A check or close whose answer has not come back after this long can be queued again.
pub const RETRY_AFTER_SECS: i64 = 120;
pub const MIN_COLLATERAL: u64 = 10_000_000; // 10 USDC
// An open whose answer has not come back after this long (the cluster stalled or dropped it) can be taken back by
// its owner. Mainnet answers take seconds; cluster 10000 once stalled for about 70 minutes.
pub const OPEN_TIMEOUT_SECS: i64 = 300;
// A relayer fee may not exceed this (10 USDC).
pub const MAX_RELAY_FEE: u64 = 10_000_000;
// A market's fixed fee per position may not exceed this (100 USDC).
pub const MAX_OPEN_FEE: u64 = 100_000_000;
// An x25519 public key nobody holds the private key of: take sha256("UNUSER book key v1 #i") with the top bit
// cleared for the first i that is a point on Curve25519 (i = 0), then multiply that point by 8 so it lies in
// the prime-order group, as every real x25519 public key does. The cluster refused both shortcuts: the plain
// string lands on the twist, and the unmultiplied point failed as an invalid input (`inputs`).
// tools/book_key.py recomputes it.
pub const BOOK_KEY: [u8; 32] = [
    12, 16, 90, 222, 78, 46, 252, 100, 227, 163, 4, 50, 186, 74, 222, 150, 123, 100, 77, 67, 124, 46, 9, 26, 90, 118,
    4, 243, 178, 81, 130, 112,
];

declare_id!("Hk5iuiYjqSeH2bXcENqxHPGamKJbferFPSsCuPPsnKMy");

// Network builds: the market is a single PDA, so whoever calls init_market first owns it. Only the program's
// upgrade authority may, and only with real USDC. Local builds leave both open for tests.
#[cfg(not(feature = "test-oracle"))]
pub const USDC_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

#[arcium_program]
pub mod unuser {
    use super::*;

    pub fn init_open_pos_comp_def(ctx: Context<InitOpenPosCompDef>) -> Result<()> {
        init_computation_def(ctx.accounts, circuit_source("open_pos", circuit_hash!("open_pos")))?;
        Ok(())
    }

    pub fn init_chk128_comp_def(ctx: Context<InitChk128CompDef>) -> Result<()> {
        init_computation_def(ctx.accounts, circuit_source("chk128", circuit_hash!("chk128")))?;
        Ok(())
    }

    pub fn init_close_pnl_comp_def(ctx: Context<InitClosePnlCompDef>) -> Result<()> {
        init_computation_def(ctx.accounts, circuit_source("close_pnl", circuit_hash!("close_pnl")))?;
        Ok(())
    }

    pub fn init_market(
        ctx: Context<InitMarket>,
        fee_bps: u16,
        borrow_bps_per_hour: u16,
        keeper_bps: u16,
        lp_cooldown_secs: i64,
        max_price_age: u16,
        open_fee: u64,
        max_open_coll_bps: u16,
        max_leverage: u8,
        fill_delay_secs: u16,
        fill_window_secs: u16,
    ) -> Result<()> {
        #[cfg(not(feature = "test-oracle"))]
        {
            let data = UpgradeableLoaderState::try_deserialize(&mut &ctx.accounts.program_data.try_borrow_data()?[..])?;
            let owner = match data {
                UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. } => upgrade_authority_address,
                _ => None,
            };
            require!(owner == Some(ctx.accounts.authority.key()), ErrorCode::BadConfig);
            require_keys_eq!(ctx.accounts.usdc_mint.key(), USDC_MINT, ErrorCode::BadConfig);
        }
        // The oracle must already read as a price (any age), so a market can never point at the wrong account.
        read_oracle(&ctx.accounts.oracle, 0, i64::MAX)?;
        let m = &mut ctx.accounts.market;
        m.authority = ctx.accounts.authority.key();
        m.usdc_mint = ctx.accounts.usdc_mint.key();
        m.vault = ctx.accounts.vault.key();
        m.oracle = ctx.accounts.oracle.key();
        m.bump = ctx.bumps.market;
        ctx.accounts.tree.load_init()?.init()?;
        m.set(fee_bps, borrow_bps_per_hour, keeper_bps, lp_cooldown_secs, max_price_age, open_fee, max_open_coll_bps, max_leverage,
              fill_delay_secs, fill_window_secs, false)
    }

    /// The market authority changes the market's settings. `opens_paused` stops new positions (closes, checks,
    /// liquidations and LP moves keep working), for an emergency such as a stalled cluster. A changed fee applies to
    /// closes from then on.
    pub fn set_params(
        ctx: Context<SetParams>,
        fee_bps: u16,
        borrow_bps_per_hour: u16,
        keeper_bps: u16,
        lp_cooldown_secs: i64,
        max_price_age: u16,
        open_fee: u64,
        max_open_coll_bps: u16,
        max_leverage: u8,
        fill_delay_secs: u16,
        fill_window_secs: u16,
        opens_paused: bool,
    ) -> Result<()> {
        ctx.accounts.market.set(fee_bps, borrow_bps_per_hour, keeper_bps, lp_cooldown_secs, max_price_age, open_fee, max_open_coll_bps,
            max_leverage, fill_delay_secs, fill_window_secs, opens_paused)?;
        emit!(ParamsEvent { fee_bps, borrow_bps_per_hour, keeper_bps, max_price_age, open_fee, max_open_coll_bps, max_leverage,
            fill_delay_secs, fill_window_secs, opens_paused });
        Ok(())
    }

    #[cfg(feature = "test-oracle")]
    pub fn init_test_oracle(ctx: Context<InitTestOracle>, price: u64) -> Result<()> {
        let o = &mut ctx.accounts.oracle;
        o.authority = ctx.accounts.authority.key();
        o.price = price;
        o.publish_time = Clock::get()?.unix_timestamp;
        Ok(())
    }

    #[cfg(feature = "test-oracle")]
    pub fn set_test_price(ctx: Context<SetTestPrice>, price: u64) -> Result<()> {
        let o = &mut ctx.accounts.oracle;
        o.price = price;
        o.publish_time = Clock::get()?.unix_timestamp;
        Ok(())
    }

    /// The client creates the book account at full size; this ties it to the market.
    pub fn init_book(ctx: Context<InitBook>) -> Result<()> {
        let mut book = ctx.accounts.book.load_init()?;
        book.market = ctx.accounts.market.key();
        book.authority = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn lp_deposit(ctx: Context<LpDeposit>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        // A pool wiped out while shares remain would give part of this deposit to those shares.
        require!(!(ctx.accounts.market.pool_balance == 0 && ctx.accounts.market.lp_shares > 0), ErrorCode::PoolEmpty);
        token::transfer(ctx.accounts.pay_in(), amount)?;
        let m = &mut ctx.accounts.market;
        let shares = if m.lp_shares == 0 {
            amount
        } else {
            (amount as u128 * m.lp_shares as u128 / m.pool_balance as u128) as u64
        };
        m.lp_shares += shares;
        m.pool_balance += amount;
        let lp = &mut ctx.accounts.lp;
        lp.owner = ctx.accounts.owner.key();
        lp.shares += shares;
        lp.last_deposit = Clock::get()?.unix_timestamp;
        emit!(LpEvent { owner: lp.owner, amount, shares, deposit: true });
        Ok(())
    }

    pub fn lp_withdraw(ctx: Context<LpWithdraw>, shares: u64) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        require!(shares > 0 && shares <= ctx.accounts.lp.shares, ErrorCode::ZeroAmount);
        require!(now - ctx.accounts.lp.last_deposit >= ctx.accounts.market.lp_cooldown_secs, ErrorCode::Cooldown);
        let (pool, total, bump) = (ctx.accounts.market.pool_balance, ctx.accounts.market.lp_shares, ctx.accounts.market.bump);
        let amount = (shares as u128 * pool as u128 / total as u128) as u64;
        // The pool that stays must still back the collateral of every open position under the exposure cap.
        require!(ctx.accounts.market.within_cap(ctx.accounts.market.open_coll, pool - amount), ErrorCode::ExposureCap);
        let seeds: &[&[u8]] = &[b"market", &[bump]];
        token::transfer(ctx.accounts.pay_out().with_signer(&[seeds]), amount)?;
        ctx.accounts.lp.shares -= shares;
        let m = &mut ctx.accounts.market;
        m.lp_shares -= shares;
        m.pool_balance -= amount;
        emit!(LpEvent { owner: ctx.accounts.lp.owner, amount, shares, deposit: false });
        Ok(())
    }

    /// Money in: USDC from any wallet becomes a note for `owner` = Poseidon(secret). This is the one place a
    /// wallet touches the exchange, and all it shows is that some amount went in.
    pub fn deposit(ctx: Context<Deposit>, owner: [u8; 32], amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::ZeroAmount);
        token::transfer(ctx.accounts.pay_in(), amount)?;
        ctx.accounts.tree.load_mut()?.credit(&owner, amount)?;
        ctx.accounts.market.note_balance += amount;
        Ok(())
    }

    /// Money out: a spend of `amount` bound to the receiving token account. Anyone can send it; the receiver
    /// has no link to the wallet that deposited. `fee` goes to the relayer as a note for `relayer`. With
    /// `amount` zero this only merges two notes into one.
    pub fn withdraw(ctx: Context<Withdraw>, spend: Spend, amount: u64, fee: u64, relayer: [u8; 32]) -> Result<()> {
        let x = notes::bind(&[b"withdraw", ctx.accounts.receiver.key().as_ref(), &fee.to_le_bytes()]);
        notes::spend_with_fee(&mut *ctx.accounts.tree.load_mut()?, &spend, amount, fee, &relayer, &x)?;
        let seeds: &[&[u8]] = &[b"market", &[ctx.accounts.market.bump]];
        token::transfer(ctx.accounts.pay_out().with_signer(&[seeds]), amount)?;
        let m = &mut ctx.accounts.market;
        m.note_balance = m.note_balance.checked_sub(amount).ok_or(ErrorCode::BadProof)?;
        Ok(())
    }

    /// Step one of an open: the trader seals size and side, pays the collateral and the fee out of a note, and takes
    /// a slot. The position fills at the first oracle price published at least `fill_delay_secs` after this request,
    /// so nobody trades at a price they have already seen move. No Arcium accounts: a small transaction.
    ///
    /// Anyone can send this transaction. The spend is bound to every field of the order, so whoever relays it
    /// cannot change the order, the key that may close it (`close_key`, a one-time key the trader keeps), the
    /// note owner the money comes back to (`payout_owner`), or the two relayer fees: `fee` now, as a note for
    /// `relayer`, and `close_fee` out of the payout for whoever relays the close.
    #[allow(clippy::too_many_arguments)]
    pub fn request_open(
        ctx: Context<RequestOpen>,
        spend: Spend,
        slot: u16,
        version: u16,
        cts: [[u8; 32]; 2],
        pubkey: [u8; 32],
        nonce: u128,
        coll: u64,
        close_key: Pubkey,
        payout_owner: [u8; 32],
        close_fee: u64,
        fee: u64,
        relayer: [u8; 32],
    ) -> Result<()> {
        require!(close_fee <= MAX_RELAY_FEE && fee <= MAX_RELAY_FEE, ErrorCode::BadConfig);
        require!((slot as usize) < SLOTS, ErrorCode::BadSlot);
        require!(coll >= MIN_COLLATERAL, ErrorCode::ZeroAmount);
        require!(!ctx.accounts.market.opens_paused, ErrorCode::OpensPaused);
        let open_coll = ctx.accounts.market.open_coll + coll;
        require!(ctx.accounts.market.within_cap(open_coll, ctx.accounts.market.pool_balance), ErrorCode::ExposureCap);
        {
            let mut book = ctx.accounts.book.load_mut()?;
            require!(!book.is_set(slot) && book.versions[slot as usize] == version, ErrorCode::SlotTaken);
            require_keys_eq!(book.market, ctx.accounts.market.key(), ErrorCode::WrongMarket);
            book.pending += 1;
        }
        // Collateral plus the fixed fee per position, which pays the pool for the computations a position costs. The
        // fee joins the pool only when the position settles (close or liquidation), so LPs can never withdraw a fee
        // that a rejected or timed-out open still has to give back. The USDC is already in the vault: the spend
        // moves it from "owed to notes" to "held for this position".
        let open_fee = ctx.accounts.market.open_fee;
        let x = notes::bind(&[
            b"open",
            ctx.accounts.book.key().as_ref(),
            &slot.to_le_bytes(),
            &version.to_le_bytes(),
            &cts[0],
            &cts[1],
            &pubkey,
            &nonce.to_le_bytes(),
            close_key.as_ref(),
            &payout_owner,
            &close_fee.to_le_bytes(),
            &fee.to_le_bytes(),
        ]);
        notes::spend_with_fee(&mut *ctx.accounts.tree.load_mut()?, &spend, coll + open_fee, fee, &relayer, &x)?;
        let m = &mut ctx.accounts.market;
        m.note_balance = m.note_balance.checked_sub(coll + open_fee).ok_or(ErrorCode::BadProof)?;
        m.open_coll = open_coll;
        let key = ctx.accounts.position.key();
        let pos = &mut ctx.accounts.position;
        pos.owner = close_key;
        pos.payout_owner = payout_owner;
        pos.close_fee = close_fee;
        pos.payer = ctx.accounts.payer.key();
        pos.book = ctx.accounts.book.key();
        pos.slot = slot;
        pos.version = version;
        pos.coll = coll;
        pos.fee_paid = open_fee;
        pos.req_cts = cts;
        pos.req_pubkey = pubkey;
        pos.req_nonce = nonce.to_le_bytes();
        pos.requested_at = Clock::get()?.unix_timestamp;
        pos.state = PositionState::Requested as u8;
        emit!(RequestEvent { position: key, open: true });
        Ok(())
    }

    /// Step two, by anyone (the keeper does it): fills a requested open at the oracle price, which must have been
    /// published inside the request's fill window, and hands the sealed order to the cluster.
    pub fn settle_open(ctx: Context<SettleOpen>, computation_offset: u64) -> Result<()> {
        let (price, published) = oracle_quote(&ctx.accounts.oracle, &ctx.accounts.market)?;
        let max_lev = ctx.accounts.market.max_leverage as u64;
        let (book_key, pos_key) = (ctx.accounts.book.key(), ctx.accounts.position.key());
        require_keys_eq!(ctx.accounts.book.load()?.market, ctx.accounts.market.key(), ErrorCode::WrongMarket);
        let args = {
            let m = &ctx.accounts.market;
            let pos = &mut ctx.accounts.position;
            require!(pos.state == PositionState::Requested as u8, ErrorCode::NotRequested);
            in_fill_window(m, pos.requested_at, published)?;
            pos.entry = price;
            pos.opened_at = Clock::get()?.unix_timestamp;
            pos.open_offset = computation_offset;
            pos.state = PositionState::Pending as u8;
            ArgBuilder::new()
                .x25519_pubkey(pos.req_pubkey)
                .plaintext_u128(u128::from_le_bytes(pos.req_nonce))
                .encrypted_u64(pos.req_cts[0])
                .encrypted_u64(pos.req_cts[1])
                .plaintext_u64(price)
                .plaintext_u64(pos.coll)
                .plaintext_u64(max_lev)
                .x25519_pubkey(BOOK_KEY)
                .build()
        };
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        let cb = OpenPosCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount { pubkey: book_key, is_writable: true },
                CallbackAccount { pubkey: pos_key, is_writable: true },
            ],
        )?;
        queue_computation(ctx.accounts, computation_offset, args, vec![cb], 1, 0, 0)?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "open_pos")]
    pub fn open_pos_callback(
        ctx: Context<OpenPosCallback>,
        output: SignedComputationOutputs<OpenPosOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(&ctx.accounts.cluster_account, &ctx.accounts.computation_account) {
            Ok(OpenPosOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };
        let (lim, rec, ok) = (o.field_0, o.field_1, o.field_2);
        // A late answer to an open that timed out and was reclaimed must not land on a new open that reuses the same
        // slot, version and position address: only this position's own computation counts.
        let expected = derive_comp_pda!(ctx.accounts.position.open_offset, ctx.accounts.mxe_account);
        if ctx.accounts.computation_account.key() != expected {
            return Ok(());
        }
        let pos = &mut ctx.accounts.position;
        require!(pos.state == PositionState::Pending as u8, ErrorCode::NotPending);
        pos.rec_nonce = rec.nonce.to_le_bytes();
        pos.rec_cts = rec.ciphertexts;
        let mut book = ctx.accounts.book.load_mut()?;
        book.pending = book.pending.saturating_sub(1);
        let i = pos.slot as usize;
        if ok && !book.is_set(pos.slot) && book.versions[i] == pos.version {
            book.nonces[i] = lim.nonce.to_le_bytes();
            book.cts[i] = lim.ciphertexts;
            book.set(pos.slot);
            pos.state = PositionState::Open as u8;
        } else {
            pos.state = PositionState::Rejected as u8;
        }
        emit!(OpenEvent { slot: pos.slot, version: pos.version, ok: pos.state == PositionState::Open as u8 });
        Ok(())
    }

    /// A rejected open (rule broken) gives the collateral and fee back as a note, and so does an open whose answer
    /// never came (pending for OPEN_TIMEOUT_SECS) or a request nobody filled. Anyone can send it: the money can only
    /// go to the note owner named at the open. The position account closes, so a late answer finds nothing to
    /// write to.
    pub fn reclaim(ctx: Context<Reclaim>) -> Result<()> {
        let p = &ctx.accounts.position;
        let now = Clock::get()?.unix_timestamp;
        let stale = p.state == PositionState::Pending as u8 && now - p.opened_at > OPEN_TIMEOUT_SECS;
        // A request nobody filled: only once no price from its window can still be fresh enough to fill it, so the
        // trader never holds the choice between filling and walking away.
        let m = &ctx.accounts.market;
        let unfilled = p.state == PositionState::Requested as u8
            && now > p.requested_at + (m.fill_delay_secs + m.fill_window_secs + m.max_price_age) as i64;
        require!(p.state == PositionState::Rejected as u8 || stale || unfilled, ErrorCode::NotRejected);
        if stale || unfilled {
            let mut book = ctx.accounts.book.load_mut()?;
            book.pending = book.pending.saturating_sub(1);
        }
        // No service was given, so the fee comes back with the collateral.
        let (coll, fee) = (ctx.accounts.position.coll, ctx.accounts.position.fee_paid);
        ctx.accounts.tree.load_mut()?.credit(&ctx.accounts.position.payout_owner, coll + fee)?;
        let m = &mut ctx.accounts.market;
        m.note_balance += coll + fee;
        m.open_coll = m.open_coll.saturating_sub(coll);
        Ok(())
    }

    /// One check round over all 128 slots at the oracle price. Anyone may run it (keepers). The answer marks
    /// slots for liquidation; `liquidate` then settles each one.
    pub fn chk128(ctx: Context<Chk128>, computation_offset: u64) -> Result<()> {
        let price = oracle_price(&ctx.accounts.oracle, &ctx.accounts.market)?;
        let now = Clock::get()?.unix_timestamp;
        let mut b = ArgBuilder::new().x25519_pubkey(BOOK_KEY);
        {
            let mut book = ctx.accounts.book.load_mut()?;
            require_keys_eq!(book.market, ctx.accounts.market.key(), ErrorCode::WrongMarket);
            require!(book.check_offset == 0 || now - book.check_queued_at > RETRY_AFTER_SECS, ErrorCode::CheckInFlight);
            book.check_offset = computation_offset;
            book.check_queued_at = now;
            book.check_versions = book.versions;
            book.check_occupied = book.occupied;
            for n in book.nonces.iter() {
                b = b.plaintext_u128(u128::from_le_bytes(*n));
            }
        }
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        // Thresholds are in 1e-4 USD and the oracle in 1e-6 USD.
        let args = b
            .account(ctx.accounts.book.key(), BOOK_CTS_AT, SLOTS as u32 * 64)
            .plaintext_u64(price / 100)
            .build();
        let cb = Chk128Callback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount { pubkey: ctx.accounts.book.key(), is_writable: true }],
        )?;
        queue_computation(ctx.accounts, computation_offset, args, vec![cb], 1, 0, 0)?;
        emit!(CheckQueued { book: ctx.accounts.book.key(), price });
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "chk128")]
    pub fn chk128_callback(ctx: Context<Chk128Callback>, output: SignedComputationOutputs<Chk128Output>) -> Result<()> {
        let mask = match output.verify_output(&ctx.accounts.cluster_account, &ctx.accounts.computation_account) {
            Ok(Chk128Output { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };
        let mut book = ctx.accounts.book.load_mut()?;
        // An answer to an older round that was queued again is ignored.
        let expected = derive_comp_pda!(book.check_offset, ctx.accounts.mxe_account);
        if book.check_offset == 0 || ctx.accounts.computation_account.key() != expected {
            return Ok(());
        }
        // Only slots that held the same position when the round was queued count.
        let mut flagged = [0u64; SLOTS / 64];
        for i in 0..SLOTS {
            let (w, b) = (i / 64, i % 64);
            let hit = mask[w] >> b & 1 == 1 && book.check_occupied[w] >> b & 1 == 1 && book.occupied[w] >> b & 1 == 1;
            if hit && book.versions[i] == book.check_versions[i] {
                flagged[w] |= 1 << b;
            }
        }
        for w in 0..SLOTS / 64 {
            book.liq_flags[w] |= flagged[w];
        }
        book.check_offset = 0;
        emit!(CheckEvent { mask: mask.to_vec(), flagged: flagged.to_vec() });
        Ok(())
    }

    /// Settles a slot that a check marked: the collateral goes to the pool, a keeper share to the caller.
    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        let s = ctx.accounts.position.state;
        require!(s == PositionState::Open as u8 || s == PositionState::CloseRequested as u8, ErrorCode::NotOpen);
        let (slot, version, coll) = (ctx.accounts.position.slot, ctx.accounts.position.version, ctx.accounts.position.coll);
        {
            let mut book = ctx.accounts.book.load_mut()?;
            let i = slot as usize;
            require!(book.liq_flags[i / 64] >> (i % 64) & 1 == 1, ErrorCode::NotFlagged);
            require!(book.versions[i] == version, ErrorCode::SlotTaken);
            book.free(slot);
        }
        let reward = (coll as u128 * ctx.accounts.market.keeper_bps as u128 / 10_000) as u64;
        let seeds: &[&[u8]] = &[b"market", &[ctx.accounts.market.bump]];
        token::transfer(ctx.accounts.pay_keeper().with_signer(&[seeds]), reward)?;
        ctx.accounts.market.pool_balance += coll - reward + ctx.accounts.position.fee_paid;
        ctx.accounts.market.open_coll = ctx.accounts.market.open_coll.saturating_sub(coll);
        ctx.accounts.position.state = PositionState::Liquidated as u8;
        emit!(LiquidatedEvent { slot, version, coll, reward });
        Ok(())
    }

    /// Step one of a close: the holder of the position's one-time key asks (it signs, anyone pays the transaction);
    /// the exit is the first oracle price published `fill_delay_secs` later.
    /// A request nobody filled in its window can be made again. `relayer` names the note owner that collects the
    /// position's close fee; the relayer fills it in, as it is the one sending this.
    pub fn request_close(ctx: Context<RequestClose>, relayer: [u8; 32]) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let m = &ctx.accounts.market;
        let key = ctx.accounts.position.key();
        let pos = &mut ctx.accounts.position;
        let expired = pos.state == PositionState::CloseRequested as u8
            && now > pos.close_requested_at + (m.fill_delay_secs + m.fill_window_secs + m.max_price_age) as i64;
        require!(pos.state == PositionState::Open as u8 || expired, ErrorCode::NotOpen);
        pos.state = PositionState::CloseRequested as u8;
        pos.close_relayer = relayer;
        pos.close_requested_at = now;
        emit!(RequestEvent { position: key, open: false });
        Ok(())
    }

    /// Step two, by anyone (the keeper): fills the close at the oracle price from the request's window and asks the
    /// cluster for the payout (PnL minus 0.06% per leg and the hourly borrow fee); the answer turns it into a note. A close
    /// whose answer has not come after RETRY_AFTER_SECS goes again at the same exit price.
    pub fn settle_close(ctx: Context<SettleClose>, computation_offset: u64) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let quote = oracle_quote(&ctx.accounts.oracle, &ctx.accounts.market);
        let (fee_bps, borrow_per_hour) = (ctx.accounts.market.fee_bps as u64, ctx.accounts.market.borrow_bps_per_hour as u64);
        let args = {
            let m = &ctx.accounts.market;
            let pos = &mut ctx.accounts.position;
            if pos.state == PositionState::CloseRequested as u8 {
                let (price, published) = quote?;
                in_fill_window(m, pos.close_requested_at, published)?;
                pos.exit = price;
                pos.exit_at = now;
            } else {
                require!(pos.state == PositionState::Closing as u8 && now - pos.close_queued_at > RETRY_AFTER_SECS, ErrorCode::NotOpen);
            }
            let hours = ((pos.exit_at - pos.opened_at).max(0) as u64 + 3_599) / 3_600;
            let borrow_bps = borrow_per_hour * hours.max(1);
            pos.state = PositionState::Closing as u8;
            pos.close_queued_at = now;
            pos.close_offset = computation_offset;
            ArgBuilder::new()
                .plaintext_u128(u128::from_le_bytes(pos.rec_nonce))
                .encrypted_u64(pos.rec_cts[0])
                .encrypted_bool(pos.rec_cts[1])
                .plaintext_u64(pos.entry)
                .plaintext_u64(pos.exit)
                .plaintext_u64(pos.coll)
                .plaintext_u64(fee_bps)
                .plaintext_u64(borrow_bps)
                .build()
        };
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        let cb = ClosePnlCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount { pubkey: ctx.accounts.book.key(), is_writable: true },
                CallbackAccount { pubkey: ctx.accounts.position.key(), is_writable: true },
                CallbackAccount { pubkey: ctx.accounts.market.key(), is_writable: true },
                CallbackAccount { pubkey: ctx.accounts.tree.key(), is_writable: true },
            ],
        )?;
        queue_computation(ctx.accounts, computation_offset, args, vec![cb], 1, 0, 0)?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "close_pnl")]
    pub fn close_pnl_callback(
        ctx: Context<ClosePnlCallback>,
        output: SignedComputationOutputs<ClosePnlOutput>,
    ) -> Result<()> {
        let value = match output.verify_output(&ctx.accounts.cluster_account, &ctx.accounts.computation_account) {
            Ok(ClosePnlOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };
        let (state, close_offset, coll, fee, slot, version) = {
            let p = &ctx.accounts.position;
            (p.state, p.close_offset, p.coll, p.fee_paid, p.slot, p.version)
        };
        let expected = derive_comp_pda!(close_offset, ctx.accounts.mxe_account);
        if state != PositionState::Closing as u8 || ctx.accounts.computation_account.key() != expected {
            return Ok(());
        }
        // The pool pays at most what it holds plus this position's collateral.
        let owed = (value / PAYOUT_SCALE) as u64;
        let payout = owed.min(ctx.accounts.market.pool_balance + coll);
        // The payout never leaves the vault: it becomes a note for the owner named at the open, less the close
        // fee, which becomes a note for whoever relayed the close request.
        let relay = ctx.accounts.position.close_fee.min(payout);
        {
            let mut tree = ctx.accounts.tree.load_mut()?;
            if payout > relay {
                tree.credit(&ctx.accounts.position.payout_owner, payout - relay)?;
            }
            if relay > 0 {
                tree.credit(&ctx.accounts.position.close_relayer, relay)?;
            }
        }
        let m = &mut ctx.accounts.market;
        m.note_balance += payout;
        m.pool_balance = m.pool_balance + coll + fee - payout;
        m.open_coll = m.open_coll.saturating_sub(coll);
        ctx.accounts.book.load_mut()?.free(slot);
        let pos = &mut ctx.accounts.position;
        pos.state = PositionState::Closed as u8;
        pos.payout = payout;
        emit!(ClosedEvent { slot, version, payout, owed });
        Ok(())
    }

    /// The rent of a finished position (closed or liquidated) goes back to whoever paid it. The payout stays in the
    /// ClosedEvent; the account is no longer needed.
    pub fn close_record(ctx: Context<CloseRecord>) -> Result<()> {
        let s = ctx.accounts.position.state;
        require!(s == PositionState::Closed as u8 || s == PositionState::Liquidated as u8, ErrorCode::NotFinished);
        Ok(())
    }

    /// The market authority takes back the rent of a book that holds nothing: no position, no open waiting for its
    /// answer, no check round in flight.
    pub fn close_book(ctx: Context<CloseBook>) -> Result<()> {
        let book = ctx.accounts.book.load()?;
        require_keys_eq!(book.market, ctx.accounts.market.key(), ErrorCode::WrongMarket);
        require!(book.occupied == [0; SLOTS / 64] && book.pending == 0 && book.check_offset == 0, ErrorCode::BookNotEmpty);
        Ok(())
    }
}

/// Where the nodes get each circuit. Local builds (`onchain-circuits`) upload it into Arcium accounts. Network
/// builds point the nodes at the file hosted at CIRCUIT_URL, which they fetch and check against the hash compiled
/// in here: `chk128` alone is 3.15 MB, about 22 SOL of rent if it lived on chain.
#[cfg(feature = "onchain-circuits")]
fn circuit_source(_name: &str, _hash: [u8; 32]) -> Option<CircuitSource> {
    None
}
// Where the compiled circuits are hosted, set when building for a network.
#[cfg(not(feature = "onchain-circuits"))]
pub const CIRCUIT_URL: &str = env!("UNUSER_CIRCUIT_URL");
#[cfg(not(feature = "onchain-circuits"))]
fn circuit_source(name: &str, hash: [u8; 32]) -> Option<CircuitSource> {
    Some(CircuitSource::OffChain(OffChainCircuitSource { source: format!("{CIRCUIT_URL}/{name}.arcis"), hash }))
}

/// Oracle price in 1e-6 USD and its publish time, from the market's own oracle account, no older than the market
/// allows.
fn oracle_quote(oracle: &AccountInfo, market: &Market) -> Result<(u64, i64)> {
    require_keys_eq!(oracle.key(), market.oracle, ErrorCode::WrongOracle);
    read_oracle(oracle, Clock::get()?.unix_timestamp, market.max_price_age as i64)
}
fn oracle_price(oracle: &AccountInfo, market: &Market) -> Result<u64> {
    Ok(oracle_quote(oracle, market)?.0)
}

/// A request fills only at a price published inside its window: at least `fill_delay_secs` after the request (so
/// the trader could not have seen it) and at most `fill_window_secs` after that (so nobody can wait for a better one).
fn in_fill_window(m: &Market, requested_at: i64, published: i64) -> Result<()> {
    let start = requested_at + m.fill_delay_secs as i64;
    require!(published >= start, ErrorCode::NotYet);
    require!(published <= start + m.fill_window_secs as i64, ErrorCode::FillExpired);
    Ok(())
}

/// Local builds: the TestOracle account the market authority sets.
#[cfg(feature = "test-oracle")]
fn read_oracle(oracle: &AccountInfo, now: i64, max_age: i64) -> Result<(u64, i64)> {
    require_keys_eq!(*oracle.owner, crate::ID, ErrorCode::WrongOracle);
    let o = TestOracle::try_deserialize(&mut &oracle.try_borrow_data()?[..])?;
    require!(o.price > 0 && now.saturating_sub(o.publish_time) <= max_age, ErrorCode::StalePrice);
    Ok((o.price, o.publish_time))
}

/// Devnet and mainnet builds: Pyth's SOL/USD PriceUpdateV2 account, read by `pyth.rs`.
#[cfg(not(feature = "test-oracle"))]
fn read_oracle(oracle: &AccountInfo, now: i64, max_age: i64) -> Result<(u64, i64)> {
    require_keys_eq!(*oracle.owner, Pubkey::new_from_array(pyth::RECEIVER), ErrorCode::WrongOracle);
    pyth::sol_price_e6(&oracle.try_borrow_data()?, now, max_age, MAX_CONF_BPS).map_err(|e| {
        match e {
            pyth::PythError::Stale => ErrorCode::StalePrice,
            pyth::PythError::WideConf => ErrorCode::WideConfidence,
            _ => ErrorCode::WrongOracle,
        }
        .into()
    })
}

#[account(zero_copy)]
pub struct Book {
    pub occupied: [u64; SLOTS / 64],
    pub nonces: [[u8; 16]; SLOTS],
    pub cts: [[[u8; 32]; 2]; SLOTS],
    // Bumped each time a slot is freed, so an answer about an old position never touches a new one.
    pub versions: [u16; SLOTS],
    pub check_versions: [u16; SLOTS],
    pub check_occupied: [u64; SLOTS / 64],
    pub liq_flags: [u64; SLOTS / 64],
    pub check_offset: u64,
    pub check_queued_at: i64,
    pub market: Pubkey,
    pub authority: Pubkey,
    // Opens queued and not answered yet; a book closes only at zero.
    pub pending: u64,
}

impl Book {
    pub fn is_set(&self, slot: u16) -> bool {
        self.occupied[slot as usize / 64] >> (slot % 64) & 1 == 1
    }
    pub fn set(&mut self, slot: u16) {
        self.occupied[slot as usize / 64] |= 1 << (slot % 64);
    }
    pub fn free(&mut self, slot: u16) {
        let (w, b) = (slot as usize / 64, slot % 64);
        self.occupied[w] &= !(1 << b);
        self.liq_flags[w] &= !(1 << b);
        self.versions[slot as usize] = self.versions[slot as usize].wrapping_add(1);
    }
}

#[repr(u8)]
pub enum PositionState {
    Pending = 0,
    Open = 1,
    Rejected = 2,
    Closing = 3,
    Closed = 4,
    Liquidated = 5,
    // Waiting for the oracle price that fills it (open) or exits it (close).
    Requested = 6,
    CloseRequested = 7,
}

#[account]
#[derive(InitSpace)]
pub struct Market {
    pub authority: Pubkey,
    pub usdc_mint: Pubkey,
    pub vault: Pubkey,
    pub oracle: Pubkey,
    // The pool's own USDC (LP deposits plus realized trader losses minus wins); open collateral is extra.
    pub pool_balance: u64,
    // USDC owed to unspent notes: everything credited to notes minus everything spent from them.
    pub note_balance: u64,
    pub lp_shares: u64,
    pub fee_bps: u16,
    pub borrow_bps_per_hour: u16,
    pub keeper_bps: u16,
    pub lp_cooldown_secs: i64,
    pub max_price_age: u16,
    pub bump: u8,
    // Fixed USDC fee per position; it joins the pool when the position settles (refunded if the open is rejected or
    // times out).
    pub open_fee: u64,
    // Collateral of all positions not yet settled may not pass this share of the pool (public numbers only).
    pub max_open_coll_bps: u16,
    pub open_coll: u64,
    pub opens_paused: bool,
    // Leverage cap for new positions, checked inside MPC at open (1 to MAX_LEVERAGE).
    pub max_leverage: u8,
    // Opens and closes fill at the first oracle price published at least `fill_delay_secs` after the request and no
    // later than `fill_window_secs` after that.
    pub fill_delay_secs: u16,
    pub fill_window_secs: u16,
}

impl Market {
    #[allow(clippy::too_many_arguments)]
    fn set(&mut self, fee_bps: u16, borrow_bps_per_hour: u16, keeper_bps: u16, lp_cooldown_secs: i64, max_price_age: u16,
           open_fee: u64, max_open_coll_bps: u16, max_leverage: u8, fill_delay_secs: u16, fill_window_secs: u16,
           opens_paused: bool) -> Result<()> {
        require!(max_price_age >= 1 && max_price_age <= MAX_PRICE_AGE_CAP, ErrorCode::BadConfig);
        require!(fee_bps <= 100 && keeper_bps <= 1_000 && lp_cooldown_secs >= 0, ErrorCode::BadConfig);
        require!(open_fee <= MAX_OPEN_FEE && max_open_coll_bps >= 1 && max_open_coll_bps <= 10_000, ErrorCode::BadConfig);
        require!(max_leverage >= 1 && max_leverage as u64 <= MAX_LEVERAGE, ErrorCode::BadConfig);
        require!(fill_delay_secs <= 60 && fill_window_secs >= 1 && fill_window_secs <= 600, ErrorCode::BadConfig);
        self.fee_bps = fee_bps;
        self.borrow_bps_per_hour = borrow_bps_per_hour;
        self.keeper_bps = keeper_bps;
        self.lp_cooldown_secs = lp_cooldown_secs;
        self.max_price_age = max_price_age;
        self.open_fee = open_fee;
        self.max_open_coll_bps = max_open_coll_bps;
        self.max_leverage = max_leverage;
        self.fill_delay_secs = fill_delay_secs;
        self.fill_window_secs = fill_window_secs;
        self.opens_paused = opens_paused;
        Ok(())
    }
    fn within_cap(&self, open_coll: u64, pool: u64) -> bool {
        open_coll as u128 * 10_000 <= pool as u128 * self.max_open_coll_bps as u128
    }
}

/// Marks a note as spent; the address is derived from the note's nullifier.
#[account]
pub struct Spent {}

#[account]
#[derive(InitSpace)]
pub struct LpAccount {
    pub owner: Pubkey,
    pub shares: u64,
    pub last_deposit: i64,
}

#[cfg(feature = "test-oracle")]
#[account]
#[derive(InitSpace)]
pub struct TestOracle {
    pub authority: Pubkey,
    pub price: u64,
    pub publish_time: i64,
}

#[account]
#[derive(InitSpace)]
pub struct Position {
    // A one-time key chosen at the open; its signature asks for the close.
    pub owner: Pubkey,
    // Poseidon(secret) of the note that receives the payout or a refund.
    pub payout_owner: [u8; 32],
    // Whoever paid this account's rent; it goes back there.
    pub payer: Pubkey,
    // Taken out of the payout for the note owner the close's relayer names in request_close.
    pub close_fee: u64,
    pub close_relayer: [u8; 32],
    pub book: Pubkey,
    pub slot: u16,
    pub version: u16,
    pub entry: u64,
    pub coll: u64,
    pub opened_at: i64,
    pub state: u8,
    pub rec_nonce: [u8; 16],
    pub rec_cts: [[u8; 32]; 2],
    pub exit: u64,
    pub close_requested_at: i64,
    pub close_offset: u64,
    pub payout: u64,
    pub fee_paid: u64,
    pub open_offset: u64,
    // The sealed order as requested, handed to the cluster when the open fills.
    pub req_pubkey: [u8; 32],
    pub req_nonce: [u8; 16],
    pub req_cts: [[u8; 32]; 2],
    pub requested_at: i64,
    pub exit_at: i64,
    pub close_queued_at: i64,
}

#[derive(Accounts)]
pub struct InitMarket<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = 8 + Market::INIT_SPACE, seeds = [b"market"], bump)]
    pub market: Box<Account<'info, Market>>,
    pub usdc_mint: Box<Account<'info, Mint>>,
    #[account(init, payer = authority, seeds = [b"vault"], bump, token::mint = usdc_mint, token::authority = market)]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(init, payer = authority, space = 8 + std::mem::size_of::<Tree>(), seeds = [b"tree"], bump)]
    pub tree: AccountLoader<'info, Tree>,
    #[cfg(not(feature = "test-oracle"))]
    /// CHECK: this program's ProgramData account; init_market reads the upgrade authority from it.
    #[account(seeds = [crate::ID.as_ref()], bump, seeds::program = anchor_lang::solana_program::bpf_loader_upgradeable::ID)]
    pub program_data: UncheckedAccount<'info>,
    /// CHECK: stored as the market's oracle; every price read checks it against this key.
    pub oracle: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[cfg(feature = "test-oracle")]
#[derive(Accounts)]
pub struct InitTestOracle<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = 8 + TestOracle::INIT_SPACE, seeds = [b"test_oracle"], bump)]
    pub oracle: Account<'info, TestOracle>,
    pub system_program: Program<'info, System>,
}

#[cfg(feature = "test-oracle")]
#[derive(Accounts)]
pub struct SetTestPrice<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority)]
    pub oracle: Account<'info, TestOracle>,
}

#[derive(Accounts)]
pub struct InitBook<'info> {
    pub authority: Signer<'info>,
    #[account(has_one = authority)]
    pub market: Box<Account<'info, Market>>,
    #[account(zero)]
    pub book: AccountLoader<'info, Book>,
}

#[derive(Accounts)]
pub struct LpDeposit<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(mut, seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, address = market.vault)]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = market.usdc_mint, token::authority = owner)]
    pub owner_token: Box<Account<'info, TokenAccount>>,
    #[account(init_if_needed, payer = owner, space = 8 + LpAccount::INIT_SPACE, seeds = [b"lp", owner.key().as_ref()], bump)]
    pub lp: Box<Account<'info, LpAccount>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> LpDeposit<'info> {
    fn pay_in(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.key(),
            Transfer {
                from: self.owner_token.to_account_info(),
                to: self.vault.to_account_info(),
                authority: self.owner.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
pub struct LpWithdraw<'info> {
    pub owner: Signer<'info>,
    #[account(mut, seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, address = market.vault)]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = market.usdc_mint, token::authority = owner)]
    pub owner_token: Box<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [b"lp", owner.key().as_ref()], bump, has_one = owner)]
    pub lp: Box<Account<'info, LpAccount>>,
    pub token_program: Program<'info, Token>,
}

impl<'info> LpWithdraw<'info> {
    fn pay_out(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.key(),
            Transfer {
                from: self.vault.to_account_info(),
                to: self.owner_token.to_account_info(),
                authority: self.market.to_account_info(),
            },
        )
    }
}

#[queue_computation_accounts("open_pos", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct SettleOpen<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init_if_needed, space = 9, payer = payer, seeds = [&SIGN_PDA_SEED], bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account))]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account))]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account))]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_OPEN_POS))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    /// CHECK: must be the market's oracle; oracle_quote checks its key, owner and contents.
    pub oracle: UncheckedAccount<'info>,
    pub book: AccountLoader<'info, Book>,
    #[account(mut, has_one = book)]
    pub position: Box<Account<'info, Position>>,
}

#[derive(Accounts)]
#[instruction(owner: [u8; 32])]
pub struct Deposit<'info> {
    pub payer: Signer<'info>,
    #[account(mut, seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, seeds = [b"tree"], bump)]
    pub tree: AccountLoader<'info, Tree>,
    #[account(mut, address = market.vault)]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = market.usdc_mint, token::authority = payer)]
    pub payer_token: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
}

impl<'info> Deposit<'info> {
    fn pay_in(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.key(),
            Transfer {
                from: self.payer_token.to_account_info(),
                to: self.vault.to_account_info(),
                authority: self.payer.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
#[instruction(spend: Spend)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, seeds = [b"tree"], bump)]
    pub tree: AccountLoader<'info, Tree>,
    // A note is spent once: these accounts exist from then on, so a second spend cannot create them.
    #[account(init, payer = payer, space = 8, seeds = [b"spent", spend.nullifiers[0].as_ref()], bump)]
    pub spent: Account<'info, Spent>,
    #[account(init, payer = payer, space = 8, seeds = [b"spent", spend.nullifiers[1].as_ref()], bump)]
    pub spent2: Account<'info, Spent>,
    #[account(mut, address = market.vault)]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = market.usdc_mint)]
    pub receiver: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

impl<'info> Withdraw<'info> {
    fn pay_out(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.key(),
            Transfer {
                from: self.vault.to_account_info(),
                to: self.receiver.to_account_info(),
                authority: self.market.to_account_info(),
            },
        )
    }
}

#[derive(Accounts)]
#[instruction(spend: Spend, slot: u16, version: u16)]
pub struct RequestOpen<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, seeds = [b"tree"], bump)]
    pub tree: AccountLoader<'info, Tree>,
    #[account(init, payer = payer, space = 8, seeds = [b"spent", spend.nullifiers[0].as_ref()], bump)]
    pub spent: Account<'info, Spent>,
    #[account(init, payer = payer, space = 8, seeds = [b"spent", spend.nullifiers[1].as_ref()], bump)]
    pub spent2: Account<'info, Spent>,
    #[account(mut)]
    pub book: AccountLoader<'info, Book>,
    #[account(init, payer = payer, space = 8 + Position::INIT_SPACE,
        seeds = [b"pos", book.key().as_ref(), &slot.to_le_bytes(), &version.to_le_bytes()], bump)]
    pub position: Box<Account<'info, Position>>,
    pub system_program: Program<'info, System>,
}

#[callback_accounts("open_pos")]
#[derive(Accounts)]
pub struct OpenPosCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_OPEN_POS))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: validated by the Arcium program; verify_output reads it.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: instructions_sysvar, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub book: AccountLoader<'info, Book>,
    #[account(mut, has_one = book)]
    pub position: Box<Account<'info, Position>>,
}

#[derive(Accounts)]
pub struct SetParams<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [b"market"], bump = market.bump, has_one = authority)]
    pub market: Box<Account<'info, Market>>,
}

#[derive(Accounts)]
pub struct CloseRecord<'info> {
    /// CHECK: the rent payer recorded on the position.
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    #[account(mut, has_one = payer, close = payer)]
    pub position: Box<Account<'info, Position>>,
}

#[derive(Accounts)]
pub struct CloseBook<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(has_one = authority)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, close = authority)]
    pub book: AccountLoader<'info, Book>,
}

#[derive(Accounts)]
pub struct Reclaim<'info> {
    /// CHECK: the rent payer recorded on the position.
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    #[account(mut, seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, seeds = [b"tree"], bump)]
    pub tree: AccountLoader<'info, Tree>,
    #[account(mut)]
    pub book: AccountLoader<'info, Book>,
    #[account(mut, has_one = payer, has_one = book, close = payer)]
    pub position: Box<Account<'info, Position>>,
}

#[queue_computation_accounts("chk128", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct Chk128<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init_if_needed, space = 9, payer = payer, seeds = [&SIGN_PDA_SEED], bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account))]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account))]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account))]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CHK128))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    /// CHECK: must be the market's oracle; oracle_price checks its key, owner and contents.
    pub oracle: UncheckedAccount<'info>,
    #[account(mut)]
    pub book: AccountLoader<'info, Book>,
}

#[callback_accounts("chk128")]
#[derive(Accounts)]
pub struct Chk128Callback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CHK128))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: validated by the Arcium program; verify_output reads it.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: instructions_sysvar, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub book: AccountLoader<'info, Book>,
}

#[derive(Accounts)]
pub struct Liquidate<'info> {
    pub keeper: Signer<'info>,
    #[account(mut, seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, address = market.vault)]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(mut, token::mint = market.usdc_mint)]
    pub keeper_token: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub book: AccountLoader<'info, Book>,
    #[account(mut, has_one = book)]
    pub position: Box<Account<'info, Position>>,
    pub token_program: Program<'info, Token>,
}

impl<'info> Liquidate<'info> {
    fn pay_keeper(&self) -> CpiContext<'_, '_, '_, 'info, Transfer<'info>> {
        CpiContext::new(
            self.token_program.key(),
            Transfer {
                from: self.vault.to_account_info(),
                to: self.keeper_token.to_account_info(),
                authority: self.market.to_account_info(),
            },
        )
    }
}

#[queue_computation_accounts("close_pnl", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct SettleClose<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init_if_needed, space = 9, payer = payer, seeds = [&SIGN_PDA_SEED], bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account))]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account))]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account))]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CLOSE_PNL))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    /// CHECK: must be the market's oracle; oracle_price checks its key, owner and contents.
    pub oracle: UncheckedAccount<'info>,
    #[account(seeds = [b"tree"], bump)]
    pub tree: AccountLoader<'info, Tree>,
    pub book: AccountLoader<'info, Book>,
    #[account(mut, has_one = book)]
    pub position: Box<Account<'info, Position>>,
}

#[derive(Accounts)]
pub struct RequestClose<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, has_one = owner @ ErrorCode::NotOwner)]
    pub position: Box<Account<'info, Position>>,
}



#[callback_accounts("close_pnl")]
#[derive(Accounts)]
pub struct ClosePnlCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CLOSE_PNL))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: validated by the Arcium program; verify_output reads it.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: instructions_sysvar, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub book: AccountLoader<'info, Book>,
    #[account(mut, has_one = book)]
    pub position: Box<Account<'info, Position>>,
    #[account(mut, seeds = [b"market"], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut, seeds = [b"tree"], bump)]
    pub tree: AccountLoader<'info, Tree>,
}

#[init_computation_definition_accounts("open_pos", payer)]
#[derive(Accounts)]
pub struct InitOpenPosCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("chk128", payer)]
#[derive(Accounts)]
pub struct InitChk128CompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("close_pnl", payer)]
#[derive(Accounts)]
pub struct InitClosePnlCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct LpEvent {
    pub owner: Pubkey,
    pub amount: u64,
    pub shares: u64,
    pub deposit: bool,
}

#[event]
pub struct ParamsEvent {
    pub fee_bps: u16,
    pub borrow_bps_per_hour: u16,
    pub keeper_bps: u16,
    pub max_price_age: u16,
    pub open_fee: u64,
    pub max_open_coll_bps: u16,
    pub max_leverage: u8,
    pub fill_delay_secs: u16,
    pub fill_window_secs: u16,
    pub opens_paused: bool,
}

#[event]
pub struct RequestEvent {
    pub position: Pubkey,
    pub open: bool,
}

#[event]
pub struct OpenEvent {
    pub slot: u16,
    pub version: u16,
    pub ok: bool,
}

#[event]
pub struct CheckQueued {
    pub book: Pubkey,
    pub price: u64,
}

#[event]
pub struct CheckEvent {
    pub mask: Vec<u64>,
    pub flagged: Vec<u64>,
}

#[event]
pub struct LiquidatedEvent {
    pub slot: u16,
    pub version: u16,
    pub coll: u64,
    pub reward: u64,
}

#[event]
pub struct ClosedEvent {
    pub slot: u16,
    pub version: u16,
    pub payout: u64,
    pub owed: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("The computation was aborted")]
    AbortedComputation,
    #[msg("Slot index out of range")]
    BadSlot,
    #[msg("Slot already holds a position, or its version moved on")]
    SlotTaken,
    #[msg("Position is not waiting for its open answer")]
    NotPending,
    #[msg("Amount must be positive (collateral at least 10 USDC)")]
    ZeroAmount,
    #[msg("LP cooldown has not passed")]
    Cooldown,
    #[msg("Book belongs to another market")]
    WrongMarket,
    #[msg("Oracle account is not the market's")]
    WrongOracle,
    #[msg("Oracle price is stale")]
    StalePrice,
    // Unused since opens fill at the oracle price; kept so the codes after it keep their numbers.
    #[msg("Declared entry price is outside the band around the oracle")]
    EntryOutOfBand,
    #[msg("A check round on this book is still waiting for its answer")]
    CheckInFlight,
    #[msg("Position is not open")]
    NotOpen,
    #[msg("Position was not rejected, and its open has not timed out")]
    NotRejected,
    #[msg("Slot was not marked by a check")]
    NotFlagged,
    #[msg("Only the position's close key can close it")]
    NotOwner,
    #[msg("Oracle confidence band is too wide")]
    WideConfidence,
    #[msg("Market setting out of range")]
    BadConfig,
    #[msg("Position is not closed or liquidated")]
    NotFinished,
    #[msg("Book still holds a position, a pending open or a check round")]
    BookNotEmpty,
    #[msg("New positions are paused by the market authority")]
    OpensPaused,
    #[msg("Open collateral would pass the market's share of the pool")]
    ExposureCap,
    #[msg("The pool is empty while shares remain; deposits are closed")]
    PoolEmpty,
    #[msg("No oracle price inside the request's fill window yet")]
    NotYet,
    #[msg("The request's fill window has passed")]
    FillExpired,
    #[msg("Position is not waiting for its fill")]
    NotRequested,
    #[msg("The spend proof does not verify")]
    BadProof,
    #[msg("The proof was built on a root the tree no longer remembers")]
    UnknownRoot,
    #[msg("The note tree is full")]
    TreeFull,
    #[msg("A value is not a field element")]
    NotAFieldElement,
}
