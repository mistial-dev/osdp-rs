//! ACU (Access Control Unit) driver — issues commands to PDs and consumes
//! their replies. Manages SQN cycling, REPLY_DELAY enforcement, retry,
//! `osdp_BUSY` handling, and off-line detection.
//!
//! # Spec: §5.7

use crate::clock::Clock;
use crate::command::Command;
use crate::error::Error;
use crate::packet::{Address, ControlByte, CtrlFlags, PacketBuilder, ParsedPacket, Sqn};
use crate::reply::{Reply, ReplyCode};
use crate::transport::Transport;
use alloc::vec::Vec;

#[cfg(feature = "secure-channel")]
use crate::command::{Chlng, SCrypt};
#[cfg(feature = "secure-channel")]
use crate::packet::{Scb, ScsType};
#[cfg(feature = "secure-channel")]
use crate::reply::{CCrypt, Nak, NakErrorCode, RMacI};
#[cfg(feature = "secure-channel")]
use crate::secure::{
    Challenged, Cryptogrammed, Disconnected, Secure, SecureRandom, Session, frame,
};
#[cfg(not(feature = "secure-channel"))]
type Scb = ();

type ParsedReply = (ReplyCode, Sqn, Option<Scb>, Vec<u8>, Vec<u8>);

/// Bytes pulled from the transport per `Transport::read` call. Sized so a
/// minimal frame fits in a single read but small enough that the stack
/// footprint stays modest.
const RX_CHUNK_LEN: usize = 64;

/// Number of consecutive `Transport::read(..) -> Ok(0)` returns we tolerate
/// inside a per-attempt budget before yielding control back to the caller as
/// `Error::Timeout`. This stops us from spinning on a non-blocking transport
/// that has nothing to deliver.
const MAX_EMPTY_READS: u8 = 4;

/// Secure-channel key selector used in SCS-CS `SEC_BLK_DATA[0]`.
#[cfg(feature = "secure-channel")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcuSecureKey {
    /// Current SCBK selected by `SEC_BLK_DATA[0] == 1`.
    Scbk,
    /// Installation default SCBK-D selected by `SEC_BLK_DATA[0] == 0`.
    ScbkD,
}

#[cfg(feature = "secure-channel")]
impl AcuSecureKey {
    const fn as_scb_data(self) -> [u8; 1] {
        match self {
            Self::ScbkD => [0],
            Self::Scbk => [1],
        }
    }
}

/// ACU-side secure-channel key material for one PD handshake.
#[cfg(feature = "secure-channel")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcuSecureKeyMaterial {
    /// Which key the ACU asks the PD to use in SCS_11 `SEC_BLK_DATA[0]`.
    pub selection: AcuSecureKey,
    /// The 16-byte SCBK value corresponding to [`Self::selection`].
    pub scbk: [u8; 16],
}

/// Application-owned ACU key policy for secure-channel handshakes.
///
/// The ACU driver does not store SCBKs or install-mode policy. Before sending
/// SCS_11 it asks the provider which key material, if any, should be used for
/// the addressed PD.
#[cfg(feature = "secure-channel")]
pub trait AcuSecureKeyProvider {
    /// Return key material for `pd_addr`, or `None` to deny SCS-CS startup.
    fn secure_key_for(&mut self, pd_addr: u8) -> Option<AcuSecureKeyMaterial>;
}

#[cfg(feature = "secure-channel")]
#[derive(Debug, Clone)]
enum AcuSecureState {
    Challenged {
        session: Session<Challenged>,
        key: AcuSecureKey,
    },
    Cryptogrammed {
        session: Session<Cryptogrammed>,
        key: AcuSecureKey,
    },
    Secure(Session<Secure>),
}

#[cfg(feature = "secure-channel")]
const SCS14_STATUS_SUCCESS: [u8; 1] = [0x01];
#[cfg(feature = "secure-channel")]
const SCS14_STATUS_FAILURE: [u8; 1] = [0xff];

#[cfg(feature = "secure-channel")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scs14Status {
    Success,
    Failure,
}

/// Per-PD bookkeeping owned by the ACU driver.
#[derive(Debug, Clone)]
pub struct PdState {
    /// Next SQN to send.
    pub next_sqn: Sqn,
    /// Whether the PD prefers CRC trailers.
    pub use_crc: bool,
    /// Last successful exchange (ms, from the [`Clock`]).
    pub last_seen_ms: u64,
    /// Strictly true once `last_seen_ms` has been set at least once.
    seen_at_least_once: bool,
    #[cfg(feature = "secure-channel")]
    secure_state: Option<AcuSecureState>,
}

impl Default for PdState {
    fn default() -> Self {
        Self {
            next_sqn: Sqn::ZERO,
            use_crc: true,
            last_seen_ms: 0,
            seen_at_least_once: false,
            #[cfg(feature = "secure-channel")]
            secure_state: None,
        }
    }
}

impl PdState {
    /// Advance SQN.
    pub fn bump_sqn(&mut self) {
        self.next_sqn = self.next_sqn.next();
    }

    /// Mark the PD as seen.
    pub fn mark_seen(&mut self, now_ms: u64) {
        self.last_seen_ms = now_ms;
        self.seen_at_least_once = true;
    }

    /// `true` once we've ever heard from the PD and the last exchange is
    /// older than [`crate::OFFLINE_THRESHOLD_MS`]. Returns `false` while we
    /// are still in the initial-connect window.
    pub fn is_offline(&self, now_ms: u64) -> bool {
        self.seen_at_least_once
            && now_ms.saturating_sub(self.last_seen_ms) >= crate::OFFLINE_THRESHOLD_MS as u64
    }

    /// Reset to the freshly-booted state. Call this when an off-line PD
    /// should be re-discovered from scratch.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// True once the SCS-CS handshake has completed.
    #[cfg(feature = "secure-channel")]
    pub fn is_secure(&self) -> bool {
        self.secure_session().is_some()
    }

    /// Borrow the established ACU-side secure session, if present.
    #[cfg(feature = "secure-channel")]
    pub fn secure_session(&self) -> Option<&Session<Secure>> {
        match &self.secure_state {
            Some(AcuSecureState::Secure(session)) => Some(session),
            _ => None,
        }
    }
}

/// Outcome of a single command/reply exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExchangeOutcome {
    /// PD answered with a typed reply.
    Reply(Reply),
    /// PD answered with `osdp_BUSY`. Caller may try again later.
    Busy,
    /// No reply within the configured budget after exhausting retries.
    Timeout,
    /// PD has been silent for ≥ [`crate::OFFLINE_THRESHOLD_MS`].
    Offline,
}

/// Configuration for retry policy.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Number of *additional* attempts after the first (so `0` = no retry).
    pub max_retries: u8,
    /// Optional cap on how long to spend retrying a single command (ms). `0`
    /// disables the cap; the default REPLY_DELAY budget per attempt still
    /// applies.
    pub overall_budget_ms: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 2,
            overall_budget_ms: 0,
        }
    }
}

/// ACU driver.
pub struct Acu<T: Transport, C: Clock> {
    transport: T,
    clock: C,
    /// Reply-delay budget per attempt, in milliseconds.
    pub reply_delay_ms: u32,
    /// Retry policy applied by [`Acu::exchange`].
    pub retry: RetryConfig,
    rx_buf: Vec<u8>,
}

impl<T: Transport, C: Clock> Acu<T, C> {
    /// New driver with default reply delay and retry policy.
    pub fn new(transport: T, clock: C) -> Self {
        Self {
            transport,
            clock,
            reply_delay_ms: crate::REPLY_DELAY_MS,
            retry: RetryConfig::default(),
            rx_buf: Vec::with_capacity(crate::MAX_BUS_PACKET),
        }
    }

    /// Borrow the underlying transport.
    pub fn transport(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Borrow the clock.
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Encode and send `command` to `pd_addr` once. Returns the bytes written.
    pub fn send_to(
        &mut self,
        pd_addr: u8,
        pd: &mut PdState,
        command: &Command,
    ) -> Result<Vec<u8>, Error> {
        #[cfg(feature = "secure-channel")]
        if pd.is_secure() {
            return self.send_secure_with_sqn(pd_addr, pd, pd.next_sqn, command);
        }
        self.send_with_sqn(pd_addr, pd.use_crc, pd.next_sqn, command)
    }

    fn send_with_sqn(
        &mut self,
        pd_addr: u8,
        use_crc: bool,
        sqn: Sqn,
        command: &Command,
    ) -> Result<Vec<u8>, Error> {
        let addr = Address::pd(pd_addr)?;
        let mut flags = CtrlFlags::empty();
        if use_crc {
            flags |= CtrlFlags::USE_CRC;
        }
        let ctrl = ControlByte::new(sqn, flags);
        let data = command.encode_data()?;
        let bytes = PacketBuilder::plain(addr, ctrl, command.code().as_byte(), data).encode()?;
        self.transport.write_all(&bytes)?;
        Ok(bytes)
    }

    #[cfg(feature = "secure-channel")]
    fn send_secure_with_sqn(
        &mut self,
        pd_addr: u8,
        pd: &mut PdState,
        sqn: Sqn,
        command: &Command,
    ) -> Result<Vec<u8>, Error> {
        let session = match pd.secure_state.take() {
            Some(AcuSecureState::Secure(session)) => session,
            other => {
                pd.secure_state = other;
                return Err(Error::SecureSession(
                    crate::error::SecureSessionError::NotSecure,
                ));
            }
        };
        let mut session = session;
        let data = command.encode_data()?;
        let encrypt = !data.is_empty();
        let bytes = frame::seal(
            &mut session,
            Address::pd(pd_addr)?,
            sqn,
            frame::Direction::AcuToPd,
            encrypt,
            command.code().as_byte(),
            &data,
        );
        pd.secure_state = Some(AcuSecureState::Secure(session));
        let bytes = bytes?;
        self.transport.write_all(&bytes)?;
        Ok(bytes)
    }

    /// Send SCS_11 / `osdp_CHLNG` and remember the challenged ACU state.
    ///
    /// OSDP v2.2 Annex D.1.3.1 uses `SEC_BLK_DATA[0]` to select the SCBK
    /// (`1`) or SCBK-D (`0`) for this secure-channel connection sequence.
    #[cfg(feature = "secure-channel")]
    pub fn send_secure_challenge<K: AcuSecureKeyProvider + ?Sized, R: SecureRandom>(
        &mut self,
        pd_addr: u8,
        pd: &mut PdState,
        keys: &mut K,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let key = keys.secure_key_for(pd_addr).ok_or(Error::SecureSession(
            crate::error::SecureSessionError::KeyUnavailable,
        ))?;
        self.send_secure_challenge_with_key_material(pd_addr, pd, key, rng)
    }

    #[cfg(feature = "secure-channel")]
    fn send_secure_challenge_with_key_material<R: SecureRandom>(
        &mut self,
        pd_addr: u8,
        pd: &mut PdState,
        key: AcuSecureKeyMaterial,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut rnd_a = [0u8; 8];
        rng.fill_secure_random(&mut rnd_a)?;
        let session = Session::<Disconnected>::new(key.scbk).challenge(rnd_a);
        let bytes = self.send_secure_handshake_with_sqn(
            pd_addr,
            pd.use_crc,
            pd.next_sqn,
            ScsType::Scs11,
            key.selection,
            &Command::Chlng(Chlng::new(rnd_a)),
        )?;
        pd.secure_state = Some(AcuSecureState::Challenged {
            session,
            key: key.selection,
        });
        Ok(bytes)
    }

    /// Receive SCS_12 / `osdp_CCRYPT` and verify the PD cryptogram.
    #[cfg(feature = "secure-channel")]
    pub fn receive_secure_ccrypt(&mut self, pd: &mut PdState) -> Result<(), Error> {
        let (reply_code, sqn, scb, data, _raw) = self.recv_loop_with_scb()?;
        self.require_sqn(pd.next_sqn, reply_code, sqn)?;
        let (session, key) = match pd.secure_state.take() {
            Some(AcuSecureState::Challenged { session, key }) => (session, key),
            other => {
                pd.secure_state = other;
                return Err(Error::SecureSession(
                    crate::error::SecureSessionError::BadTransition,
                ));
            }
        };
        self.require_scb(scb.as_ref(), ScsType::Scs12, key)?;
        if reply_code != ReplyCode::CCrypt {
            pd.secure_state = Some(AcuSecureState::Challenged { session, key });
            return Err(Error::UnknownReply(reply_code.as_byte()));
        }
        let ccrypt = CCrypt::decode(&data)?;
        match session.receive_ccrypt(&ccrypt) {
            Ok(session) => {
                pd.secure_state = Some(AcuSecureState::Cryptogrammed { session, key });
                pd.mark_seen(self.clock.now_ms());
                pd.bump_sqn();
                Ok(())
            }
            Err((session, err)) => {
                pd.secure_state = None;
                let _ = session;
                Err(Error::from(err))
            }
        }
    }

    /// Send SCS_13 / `osdp_SCRYPT` using the verified PD cryptogram state.
    #[cfg(feature = "secure-channel")]
    pub fn send_secure_scrypt(&mut self, pd_addr: u8, pd: &mut PdState) -> Result<Vec<u8>, Error> {
        let (server_cryptogram, key) = match pd.secure_state.as_ref() {
            Some(AcuSecureState::Cryptogrammed { session, key }) => {
                (session.server_cryptogram(), *key)
            }
            _ => {
                return Err(Error::SecureSession(
                    crate::error::SecureSessionError::BadTransition,
                ));
            }
        };
        self.send_secure_handshake_with_sqn(
            pd_addr,
            pd.use_crc,
            pd.next_sqn,
            ScsType::Scs13,
            key,
            &Command::SCrypt(SCrypt::new(server_cryptogram)),
        )
    }

    /// Receive SCS_14 / `osdp_RMAC_I` and store the established secure state.
    #[cfg(feature = "secure-channel")]
    pub fn receive_secure_rmac_i(&mut self, pd: &mut PdState) -> Result<(), Error> {
        let (reply_code, sqn, scb, data, _raw) = self.recv_loop_with_scb()?;
        self.require_sqn(pd.next_sqn, reply_code, sqn)?;
        let (session, key) = match pd.secure_state.take() {
            Some(AcuSecureState::Cryptogrammed { session, key }) => (session, key),
            other => {
                pd.secure_state = other;
                return Err(Error::SecureSession(
                    crate::error::SecureSessionError::BadTransition,
                ));
            }
        };
        if reply_code == ReplyCode::Nak {
            let nak = Nak::decode(&data)?;
            if nak.error == NakErrorCode::SecurityBlockTypeNotSupported {
                // OSDP v2.2 Annex D.1.3.4 allows a PD to report failed
                // Server Cryptogram verification with NAK 0x05 instead of an
                // SCS_14 failure status. Either form means SCS-CS failed.
                pd.secure_state = None;
                return Err(Error::Nak {
                    code: nak.error.as_byte(),
                });
            }
            pd.secure_state = Some(AcuSecureState::Cryptogrammed { session, key });
            return Err(Error::Nak {
                code: nak.error.as_byte(),
            });
        }
        match self.require_scs14_status(scb.as_ref())? {
            Scs14Status::Success => {}
            Scs14Status::Failure => {
                pd.secure_state = None;
                return Err(Error::SecureSession(
                    crate::error::SecureSessionError::BadCryptogram,
                ));
            }
        }
        if reply_code != ReplyCode::RMacI {
            pd.secure_state = Some(AcuSecureState::Cryptogrammed { session, key });
            return Err(Error::UnknownReply(reply_code.as_byte()));
        }
        let rmac_i = RMacI::decode(&data)?;
        match session.confirm_rmac_i(&rmac_i.r_mac_i) {
            Ok(session) => {
                pd.secure_state = Some(AcuSecureState::Secure(session));
                pd.mark_seen(self.clock.now_ms());
                pd.bump_sqn();
                Ok(())
            }
            Err((session, err)) => {
                pd.secure_state = None;
                let _ = session;
                Err(Error::from(err))
            }
        }
    }

    /// Run the ACU side of the SCS-CS handshake through SCS_11..SCS_14.
    ///
    /// This is a convenience wrapper around the four explicit handshake
    /// methods for transports that can synchronously deliver each PD reply
    /// between ACU writes. Event-loop style integrations can continue to call
    /// the individual steps directly. OSDP v2.2 Annex D.1.3 defines this
    /// order: CHLNG, CCRYPT, SCRYPT, then RMAC_I.
    #[cfg(feature = "secure-channel")]
    pub fn establish_secure_channel<K: AcuSecureKeyProvider + ?Sized, R: SecureRandom>(
        &mut self,
        pd_addr: u8,
        pd: &mut PdState,
        keys: &mut K,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.send_secure_challenge(pd_addr, pd, keys, rng)?;
        self.receive_secure_ccrypt(pd)?;
        self.send_secure_scrypt(pd_addr, pd)?;
        self.receive_secure_rmac_i(pd)
    }

    #[cfg(feature = "secure-channel")]
    fn send_secure_handshake_with_sqn(
        &mut self,
        pd_addr: u8,
        use_crc: bool,
        sqn: Sqn,
        scs: ScsType,
        key: AcuSecureKey,
        command: &Command,
    ) -> Result<Vec<u8>, Error> {
        let addr = Address::pd(pd_addr)?;
        let mut flags = CtrlFlags::HAS_SCB;
        if use_crc {
            flags |= CtrlFlags::USE_CRC;
        }
        let bytes = PacketBuilder {
            addr,
            ctrl: ControlByte::new(sqn, flags),
            scb: Some(Scb::new(scs, key.as_scb_data())),
            code: command.code().as_byte(),
            data: command.encode_data()?,
        }
        .encode()?;
        self.transport.write_all(&bytes)?;
        Ok(bytes)
    }

    /// Drain whatever bytes the transport has, then attempt to parse one
    /// reply. Returns `Err(Error::Timeout)` once the per-attempt
    /// reply-delay budget elapses without a complete packet.
    ///
    /// The loop reads up to a small fixed number of times per call to
    /// drain a transport that may return short reads. When the underlying
    /// transport returns `Ok(0)` (no more bytes immediately ready), we
    /// check the deadline and either return `Timeout` or immediately
    /// return — the caller is expected to call us again later.
    pub fn receive(&mut self, pd: &mut PdState) -> Result<Reply, Error> {
        let (reply_code, _sqn, _scb, data, _raw) = self.recv_loop_with_scb()?;
        #[cfg(feature = "secure-channel")]
        let data = self.unseal_secure_reply_if_established(pd, _scb.as_ref(), &data, &_raw)?;
        let now = self.clock.now_ms();
        pd.mark_seen(now);
        pd.bump_sqn();
        Reply::decode(reply_code, &data)
    }

    /// Inner read/parse loop shared by reply receive paths. Drains the
    /// transport into `rx_buf` until a
    /// complete packet can be parsed, the per-attempt reply-delay budget is
    /// exhausted, or the transport has signalled "no data" too many times.
    ///
    /// Returns the parsed reply metadata, DATA bytes, and original frame bytes.
    /// SQN and secure-channel policy are left to the caller.
    fn recv_loop_with_scb(&mut self) -> Result<ParsedReply, Error> {
        let start = self.clock.now_ms();
        let mut empty_reads = 0u8;
        loop {
            if let Some(packet) = self.try_parse_packet_with_scb()? {
                return Ok(packet);
            }
            let mut tmp = [0u8; RX_CHUNK_LEN];
            let n = self.transport.read(&mut tmp)?;
            if n > 0 {
                self.rx_buf.extend_from_slice(&tmp[..n]);
                empty_reads = 0;
                continue;
            }
            if self.clock.now_ms().saturating_sub(start) >= self.reply_delay_ms as u64 {
                return Err(Error::Timeout);
            }
            empty_reads = empty_reads.saturating_add(1);
            if empty_reads >= MAX_EMPTY_READS {
                return Err(Error::Timeout);
            }
        }
    }

    /// Run a command/reply round-trip with full retry & off-line policy.
    ///
    /// - On a clean reply, returns [`ExchangeOutcome::Reply`].
    /// - On `osdp_BUSY`, returns [`ExchangeOutcome::Busy`] without bumping SQN
    ///   (per Annex A.2: BUSY's SQN is always 0). The caller decides whether
    ///   to retry now or service other PDs first.
    /// - On timeout, retries up to [`RetryConfig::max_retries`] additional
    ///   times *re-using the same SQN* — that asks the PD to repeat its
    ///   prior reply, per §5.7 / Table 2.
    /// - When the PD has been silent for ≥ [`crate::OFFLINE_THRESHOLD_MS`],
    ///   returns [`ExchangeOutcome::Offline`].
    ///
    #[cfg_attr(feature = "_docs", aquamarine::aquamarine)]
    /// ```mermaid
    /// flowchart TD
    ///     enter([exchange]) --> off{is_offline?}
    ///     off -- yes --> O[Offline]
    ///     off -- no --> send[send_with_sqn]
    ///     send --> recv[recv_one_with_sqn]
    ///     recv --> kind{reply?}
    ///     kind -- BUSY --> bu["Busy<br/>(SQN unchanged)"]
    ///     kind -- typed --> ok["Reply<br/>(bump_sqn)"]
    ///     kind -- Timeout --> retry{"retries left?<br/>budget left?<br/>not offline?"}
    ///     retry -- yes --> send
    ///     retry -- no --> T[Timeout]
    /// ```
    pub fn exchange(
        &mut self,
        pd_addr: u8,
        pd: &mut PdState,
        command: &Command,
    ) -> Result<ExchangeOutcome, Error> {
        let now = self.clock.now_ms();
        if pd.is_offline(now) {
            return Ok(ExchangeOutcome::Offline);
        }

        let started = now;
        let sqn = pd.next_sqn;
        let mut attempts: u8 = 0;
        let max = self.retry.max_retries;
        let budget = self.retry.overall_budget_ms;
        let mut request: Option<Vec<u8>> = None;
        #[cfg(feature = "secure-channel")]
        let mut secure_request_sent = false;

        loop {
            if let Some(bytes) = request.as_ref() {
                self.transport.write_all(bytes)?;
            } else {
                #[cfg(feature = "secure-channel")]
                let secure_send = pd.is_secure();
                #[cfg(feature = "secure-channel")]
                let bytes = if secure_send {
                    self.send_secure_with_sqn(pd_addr, pd, sqn, command)?
                } else {
                    self.send_with_sqn(pd_addr, pd.use_crc, sqn, command)?
                };
                #[cfg(feature = "secure-channel")]
                {
                    secure_request_sent = secure_send;
                }
                #[cfg(not(feature = "secure-channel"))]
                let bytes = self.send_with_sqn(pd_addr, pd.use_crc, sqn, command)?;
                request = Some(bytes);
            }

            match self.recv_one_with_sqn(pd, sqn) {
                Ok(reply) => {
                    let now = self.clock.now_ms();
                    pd.mark_seen(now);
                    if matches!(reply, Reply::Busy(_)) {
                        // BUSY does not advance the SQN.
                        return Ok(ExchangeOutcome::Busy);
                    }
                    pd.bump_sqn();
                    return Ok(ExchangeOutcome::Reply(reply));
                }
                Err(Error::Timeout) => {
                    attempts += 1;
                    let now = self.clock.now_ms();
                    if pd.is_offline(now) {
                        #[cfg(feature = "secure-channel")]
                        if secure_request_sent {
                            Self::reset_secure_after_exhausted_timeout(pd);
                        }
                        return Ok(ExchangeOutcome::Offline);
                    }
                    if attempts > max {
                        #[cfg(feature = "secure-channel")]
                        if secure_request_sent {
                            Self::reset_secure_after_exhausted_timeout(pd);
                        }
                        return Ok(ExchangeOutcome::Timeout);
                    }
                    if budget != 0 && now.saturating_sub(started) >= budget as u64 {
                        #[cfg(feature = "secure-channel")]
                        if secure_request_sent {
                            Self::reset_secure_after_exhausted_timeout(pd);
                        }
                        return Ok(ExchangeOutcome::Timeout);
                    }
                    // Re-loop with the SAME SQN to ask for a reply repeat.
                    continue;
                }
                Err(other) => return Err(other),
            }
        }
    }

    #[cfg(feature = "secure-channel")]
    fn reset_secure_after_exhausted_timeout(pd: &mut PdState) {
        // OSDP v2.2 D.1.2 terminates the secure session and destroys session
        // keys when encryption synchronization is lost; it also allows either
        // party to terminate by forcing a timeout. D.7 says an ACU that
        // identifies a secure-session issue should reset and initiate a new
        // osdp_CHLNG/SCS_11 sequence.
        pd.secure_state = None;
    }

    /// Same as [`Self::receive`] but without mutating any [`PdState`] (used
    /// inside [`Self::exchange`] which has its own bookkeeping).
    ///
    /// Enforces §5.7 / Table 2: the PD must echo the SQN we sent. `osdp_BUSY`
    /// is the documented exception — it is always SQN=0 regardless of what
    /// the ACU sent — so its SQN is not checked.
    fn recv_one_with_sqn(&mut self, _pd: &mut PdState, expected_sqn: Sqn) -> Result<Reply, Error> {
        let (reply_code, parsed_sqn, _scb, data, _raw) = self.recv_loop_with_scb()?;
        self.require_sqn(expected_sqn, reply_code, parsed_sqn)?;
        #[cfg(feature = "secure-channel")]
        let data = self.unseal_secure_reply_if_established(_pd, _scb.as_ref(), &data, &_raw)?;
        Reply::decode(reply_code, &data)
    }

    fn try_parse_packet_with_scb(&mut self) -> Result<Option<ParsedReply>, Error> {
        while let Some(som_pos) = self.rx_buf.iter().position(|&b| b == crate::SOM) {
            self.rx_buf.drain(..som_pos);
            match ParsedPacket::parse(&self.rx_buf) {
                Ok((parsed, used)) => {
                    let code = ReplyCode::from_byte(parsed.code)?;
                    let sqn = parsed.ctrl.sqn;
                    #[cfg(feature = "secure-channel")]
                    let scb = parsed.scb.map(Scb::from);
                    #[cfg(not(feature = "secure-channel"))]
                    let scb = parsed.scb.map(|_| ());
                    let data = parsed.data.to_vec();
                    let raw = self.rx_buf[..used].to_vec();
                    self.rx_buf.drain(..used);
                    return Ok(Some((code, sqn, scb, data, raw)));
                }
                Err(Error::Truncated { .. }) => return Ok(None),
                Err(Error::BadSom(_)) => {
                    self.rx_buf.remove(0);
                    continue;
                }
                // CRC/checksum failures: skip just past the SOM and resync.
                Err(Error::BadCrc { .. }) | Err(Error::BadChecksum { .. }) => {
                    self.rx_buf.remove(0);
                    continue;
                }
                Err(other) => return Err(other),
            }
        }
        Ok(None)
    }

    fn require_sqn(
        &self,
        expected_sqn: Sqn,
        reply_code: ReplyCode,
        parsed_sqn: Sqn,
    ) -> Result<(), Error> {
        if reply_code != ReplyCode::Busy && parsed_sqn != expected_sqn {
            return Err(Error::SqnMismatch {
                expected: expected_sqn.value(),
                got: parsed_sqn.value(),
            });
        }
        Ok(())
    }

    #[cfg(feature = "secure-channel")]
    fn require_scb(
        &self,
        scb: Option<&Scb>,
        expected: ScsType,
        key: AcuSecureKey,
    ) -> Result<(), Error> {
        match scb {
            Some(scb) if scb.ty == expected && scb.data == key.as_scb_data() => Ok(()),
            Some(scb) => Err(Error::BadSecurityBlock(scb.ty.as_byte())),
            None => Err(Error::SecureSession(
                crate::error::SecureSessionError::NotSecure,
            )),
        }
    }

    #[cfg(feature = "secure-channel")]
    fn require_scs14_status(&self, scb: Option<&Scb>) -> Result<Scs14Status, Error> {
        match scb {
            // OSDP v2.2 Annex D.1.3.4 defines SCS_14 SEC_BLK_DATA[0] as a
            // status byte, not the SCS_11/SCS_13 key selector: 0x01 means
            // success and 0xff means the Server Cryptogram was rejected.
            // The crate PD emits the allowed NAK 0x05 alternative on failure,
            // but ACU accepts both standard failure forms for interoperability.
            Some(scb) if scb.ty == ScsType::Scs14 && scb.data == SCS14_STATUS_SUCCESS => {
                Ok(Scs14Status::Success)
            }
            Some(scb) if scb.ty == ScsType::Scs14 && scb.data == SCS14_STATUS_FAILURE => {
                Ok(Scs14Status::Failure)
            }
            Some(scb) => Err(Error::BadSecurityBlock(scb.ty.as_byte())),
            None => Err(Error::SecureSession(
                crate::error::SecureSessionError::NotSecure,
            )),
        }
    }

    #[cfg(feature = "secure-channel")]
    fn unseal_secure_reply_if_established(
        &self,
        pd: &mut PdState,
        scb: Option<&Scb>,
        data: &[u8],
        raw: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let session = match pd.secure_state.take() {
            Some(AcuSecureState::Secure(session)) => session,
            other => {
                pd.secure_state = other;
                return Ok(data.to_vec());
            }
        };

        match scb.map(|scb| scb.ty) {
            Some(ScsType::Scs16 | ScsType::Scs18) => {}
            Some(scs) => {
                pd.secure_state = None;
                return Err(Error::BadSecurityBlock(scs.as_byte()));
            }
            None => {
                pd.secure_state = None;
                return Err(Error::SecureSession(
                    crate::error::SecureSessionError::NotSecure,
                ));
            }
        }

        let (parsed, _) = ParsedPacket::parse(raw)?;
        // OSDP v2.2 Annex D.6.1 unwrap authenticates the full secured frame
        // before DATA is consumed. Annex D.1.2 treats an invalid MAC as lost
        // secure-channel synchronization, so the ACU drops the secure state
        // and requires a new SCS-CS handshake on failure.
        match frame::unseal(session, &parsed, raw) {
            Ok((session, plaintext)) => {
                pd.secure_state = Some(AcuSecureState::Secure(session));
                Ok(plaintext)
            }
            Err(err) => {
                pd.secure_state = None;
                Err(err.error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::command::{Id, Poll};
    use crate::reply::PdId;
    use crate::transport::VecTransport;

    #[cfg(feature = "secure-channel")]
    use crate::driver::pd::{Pd, PdHandler, PdSecureConfig, PdSecureKey, PdSecureKeyProvider};
    #[cfg(feature = "secure-channel")]
    use crate::secure::SCBK_D;
    #[cfg(feature = "secure-channel")]
    use alloc::collections::VecDeque;

    #[cfg(feature = "secure-channel")]
    const TEST_SCBK: [u8; 16] = [0xA5; 16];

    #[cfg(feature = "secure-channel")]
    struct FixedRandom([u8; 8]);

    #[cfg(feature = "secure-channel")]
    impl SecureRandom for FixedRandom {
        fn fill_secure_random(&mut self, out: &mut [u8]) -> crate::error::Result<()> {
            assert_eq!(out.len(), self.0.len());
            out.copy_from_slice(&self.0);
            Ok(())
        }
    }

    #[cfg(feature = "secure-channel")]
    struct FixedAcuKeys(Option<AcuSecureKeyMaterial>);

    #[cfg(feature = "secure-channel")]
    impl AcuSecureKeyProvider for FixedAcuKeys {
        fn secure_key_for(&mut self, _pd_addr: u8) -> Option<AcuSecureKeyMaterial> {
            self.0
        }
    }

    #[cfg(feature = "secure-channel")]
    fn scbk_d_material() -> AcuSecureKeyMaterial {
        AcuSecureKeyMaterial {
            selection: AcuSecureKey::ScbkD,
            scbk: SCBK_D,
        }
    }

    #[cfg(feature = "secure-channel")]
    fn scbk_material() -> AcuSecureKeyMaterial {
        AcuSecureKeyMaterial {
            selection: AcuSecureKey::Scbk,
            scbk: TEST_SCBK,
        }
    }

    #[cfg(feature = "secure-channel")]
    #[derive(Clone)]
    struct FixedPdKeys {
        scbk: Option<[u8; 16]>,
        scbk_d: Option<[u8; 16]>,
    }

    #[cfg(feature = "secure-channel")]
    impl FixedPdKeys {
        fn scbk_d_only() -> Self {
            Self {
                scbk: None,
                scbk_d: Some(SCBK_D),
            }
        }

        fn both() -> Self {
            Self {
                scbk: Some(TEST_SCBK),
                scbk_d: Some(SCBK_D),
            }
        }
    }

    #[cfg(feature = "secure-channel")]
    impl PdSecureKeyProvider for FixedPdKeys {
        fn secure_key_for(&mut self, selection: PdSecureKey) -> Option<[u8; 16]> {
            match selection {
                PdSecureKey::Scbk => self.scbk,
                PdSecureKey::ScbkD => self.scbk_d,
            }
        }
    }

    #[test]
    fn send_poll_emits_correct_bytes() {
        let clock = MockClock::new();
        let transport = VecTransport::new();
        let mut acu = Acu::new(transport, clock);
        let mut pd = PdState::default();
        let bytes = acu.send_to(0x05, &mut pd, &Command::Poll(Poll)).unwrap();
        assert_eq!(bytes[0], crate::SOM);
        assert_eq!(bytes[1], 0x05);
        assert_eq!(bytes[4] & 0x0F, 0x04); // SQN=0, CRC=on
    }

    #[test]
    fn exchange_offline_when_silent() {
        let clock = MockClock::new();
        let transport = VecTransport::new();
        let mut acu = Acu::new(transport, clock.clone());
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };
        let mut pd = PdState::default();
        // Pretend we'd seen the PD long ago.
        pd.mark_seen(0);
        clock.set(crate::OFFLINE_THRESHOLD_MS as u64 + 1);
        let outcome = acu.exchange(0x05, &mut pd, &Command::Poll(Poll)).unwrap();
        assert_eq!(outcome, ExchangeOutcome::Offline);
    }

    #[test]
    fn timeout_then_no_more_retries_returns_timeout() {
        let clock = MockClock::new();
        let transport = VecTransport::new();
        let mut acu = Acu::new(transport, clock.clone());
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };
        let mut pd = PdState::default();
        pd.mark_seen(0);
        // Advance just enough that we're hitting the per-attempt budget but
        // not yet off-line.
        clock.set(crate::REPLY_DELAY_MS as u64 + 1);
        let outcome = acu.exchange(0x05, &mut pd, &Command::Poll(Poll)).unwrap();
        assert_eq!(outcome, ExchangeOutcome::Timeout);
    }

    #[test]
    fn exchange_rejects_reply_with_wrong_sqn() {
        // The ACU sends with SQN=1; we feed it back an ACK that claims SQN=2.
        // Per §5.7 / Table 2 this is a stale/desync'd PD and must be rejected.
        let clock = MockClock::new();
        let mut transport = VecTransport::new();
        let stale = PacketBuilder::plain(
            Address::reply(0x05).unwrap(),
            ControlByte::new(Sqn::new(2).unwrap(), CtrlFlags::USE_CRC),
            crate::reply::ReplyCode::Ack.as_byte(),
            alloc::vec::Vec::new(),
        )
        .encode()
        .unwrap();
        transport.feed(&stale);

        let mut acu = Acu::new(transport, clock);
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };
        let mut pd = PdState {
            next_sqn: Sqn::new(1).unwrap(),
            ..Default::default()
        };
        pd.mark_seen(0);

        let err = acu
            .exchange(0x05, &mut pd, &Command::Poll(Poll))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::SqnMismatch {
                expected: 1,
                got: 2
            }
        ));
    }

    #[test]
    fn exchange_accepts_busy_with_sqn_zero() {
        // BUSY always carries SQN=0 regardless of what the ACU sent
        // (Annex A.2). Verify we accept it instead of flagging SQN mismatch.
        let clock = MockClock::new();
        let mut transport = VecTransport::new();
        let busy = PacketBuilder::plain(
            Address::reply(0x05).unwrap(),
            ControlByte::new(Sqn::ZERO, CtrlFlags::USE_CRC),
            crate::reply::ReplyCode::Busy.as_byte(),
            alloc::vec::Vec::new(),
        )
        .encode()
        .unwrap();
        transport.feed(&busy);

        let mut acu = Acu::new(transport, clock);
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };
        let mut pd = PdState {
            next_sqn: Sqn::new(2).unwrap(),
            ..Default::default()
        };
        pd.mark_seen(0);

        let outcome = acu.exchange(0x05, &mut pd, &Command::Poll(Poll)).unwrap();
        assert_eq!(outcome, ExchangeOutcome::Busy);
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_handshake_round_trips_with_pd_driver() {
        struct SecurePd;
        impl PdHandler for SecurePd {
            fn on_command(&mut self, _command: &Command) -> Reply {
                Reply::Ack(crate::reply::Ack)
            }
        }

        let mut acu = Acu::new(VecTransport::new(), MockClock::new());
        let mut pd_driver = Pd::new(VecTransport::new(), MockClock::new(), 0x05, SecurePd)
            .with_secure_channel(
                PdSecureConfig { cuid: [0xC1; 8] },
                FixedPdKeys::scbk_d_only(),
            );
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_d_material()));
        let mut acu_rng = FixedRandom([0xA1; 8]);
        let mut pd_rng = FixedRandom([0xB2; 8]);

        acu.send_secure_challenge(0x05, &mut state, &mut keys, &mut acu_rng)
            .unwrap();
        acu.transport().shuffle_to(pd_driver.transport());
        assert!(pd_driver.poll_once_with_rng(&mut pd_rng).unwrap());
        pd_driver.transport().shuffle_to(acu.transport());
        acu.receive_secure_ccrypt(&mut state).unwrap();

        acu.send_secure_scrypt(0x05, &mut state).unwrap();
        acu.transport().shuffle_to(pd_driver.transport());
        assert!(pd_driver.poll_once_with_rng(&mut pd_rng).unwrap());
        pd_driver.transport().shuffle_to(acu.transport());
        acu.receive_secure_rmac_i(&mut state).unwrap();

        assert!(state.is_secure());
        assert_eq!(state.next_sqn.value(), 2);
    }

    #[cfg(feature = "secure-channel")]
    struct SecurePd;

    #[cfg(feature = "secure-channel")]
    impl PdHandler for SecurePd {
        fn on_command(&mut self, command: &Command) -> Reply {
            match command {
                Command::Id(_) => Reply::PdId(PdId {
                    vendor_oui: [0x00, 0x06, 0x8E],
                    model: 0x12,
                    version: 0x34,
                    serial: 0xCAFE_BABE,
                    firmware: [1, 2, 3],
                }),
                _ => Reply::Ack(crate::reply::Ack),
            }
        }
    }

    #[cfg(feature = "secure-channel")]
    struct LoopbackPdTransport {
        pd: Pd<VecTransport, MockClock, SecurePd, FixedPdKeys>,
        rng: FixedRandom,
        incoming: VecDeque<u8>,
        writes: Vec<Vec<u8>>,
        replies: Vec<Vec<u8>>,
        drop_next_reply: bool,
    }

    #[cfg(feature = "secure-channel")]
    impl LoopbackPdTransport {
        fn new() -> Self {
            Self {
                pd: Pd::new(VecTransport::new(), MockClock::new(), 0x05, SecurePd)
                    .with_secure_channel(PdSecureConfig { cuid: [0xC1; 8] }, FixedPdKeys::both()),
                rng: FixedRandom([0xB2; 8]),
                incoming: VecDeque::new(),
                writes: Vec::new(),
                replies: Vec::new(),
                drop_next_reply: false,
            }
        }

        fn drop_next_reply(&mut self) {
            self.drop_next_reply = true;
        }

        fn last_write(&self) -> &[u8] {
            self.writes.last().unwrap()
        }

        fn last_reply(&self) -> &[u8] {
            self.replies.last().unwrap()
        }
    }

    #[cfg(feature = "secure-channel")]
    impl Transport for LoopbackPdTransport {
        fn write_all(&mut self, bytes: &[u8]) -> Result<(), Error> {
            self.writes.push(bytes.to_vec());
            self.pd.transport().feed(bytes);
            self.pd.poll_once_with_rng(&mut self.rng)?;
            let reply: Vec<u8> = self.pd.transport().outgoing.drain(..).collect();
            if self.drop_next_reply {
                self.drop_next_reply = false;
            } else {
                self.incoming.extend(reply.iter().copied());
            }
            self.replies.push(reply);
            Ok(())
        }

        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            let n = buf.len().min(self.incoming.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.incoming.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    #[cfg(feature = "secure-channel")]
    struct SilentTransport {
        writes: Vec<Vec<u8>>,
        clock: Option<MockClock>,
        advance_to_ms: u64,
    }

    #[cfg(feature = "secure-channel")]
    impl SilentTransport {
        fn new() -> Self {
            Self {
                writes: Vec::new(),
                clock: None,
                advance_to_ms: 0,
            }
        }

        fn advancing(clock: MockClock, advance_to_ms: u64) -> Self {
            Self {
                writes: Vec::new(),
                clock: Some(clock),
                advance_to_ms,
            }
        }
    }

    #[cfg(feature = "secure-channel")]
    impl Transport for SilentTransport {
        fn write_all(&mut self, bytes: &[u8]) -> Result<(), Error> {
            self.writes.push(bytes.to_vec());
            Ok(())
        }

        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Error> {
            if let Some(clock) = self.clock.take() {
                clock.set(self.advance_to_ms);
            }
            Ok(0)
        }
    }

    #[cfg(feature = "secure-channel")]
    fn establish_secure_state() -> PdState {
        let mut acu = Acu::new(LoopbackPdTransport::new(), MockClock::new());
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_d_material()));
        let mut rng = FixedRandom([0xA1; 8]);

        acu.establish_secure_channel(0x05, &mut state, &mut keys, &mut rng)
            .unwrap();

        assert!(state.is_secure());
        state
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn establish_secure_channel_runs_full_handshake() {
        let mut acu = Acu::new(LoopbackPdTransport::new(), MockClock::new());
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_d_material()));
        let mut rng = FixedRandom([0xA1; 8]);

        acu.establish_secure_channel(0x05, &mut state, &mut keys, &mut rng)
            .unwrap();

        assert!(state.is_secure());
        assert_eq!(state.next_sqn.value(), 2);

        let writes = &acu.transport().writes;
        assert_eq!(writes.len(), 2);
        let (parsed, _) = ParsedPacket::parse(&writes[0]).unwrap();
        let scb = parsed.scb.unwrap();
        assert_eq!(scb.ty, ScsType::Scs11);
        assert_eq!(scb.data, &[0]);
        let (parsed, _) = ParsedPacket::parse(&writes[1]).unwrap();
        assert_eq!(parsed.scb.unwrap().ty, ScsType::Scs13);
        let replies = &acu.transport().replies;
        let (parsed, _) = ParsedPacket::parse(&replies[1]).unwrap();
        let scb = parsed.scb.unwrap();
        assert_eq!(scb.ty, ScsType::Scs14);
        assert_eq!(scb.data, &[1]);
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn establish_secure_channel_uses_current_scbk_when_provider_selects_it() {
        let mut acu = Acu::new(LoopbackPdTransport::new(), MockClock::new());
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_material()));
        let mut rng = FixedRandom([0xA1; 8]);

        acu.establish_secure_channel(0x05, &mut state, &mut keys, &mut rng)
            .unwrap();

        assert!(state.is_secure());
        assert_eq!(state.next_sqn.value(), 2);

        let writes = &acu.transport().writes;
        assert_eq!(writes.len(), 2);
        let (parsed, _) = ParsedPacket::parse(&writes[0]).unwrap();
        let scb = parsed.scb.unwrap();
        assert_eq!(scb.ty, ScsType::Scs11);
        assert_eq!(scb.data, &[1]);
        let replies = &acu.transport().replies;
        let (parsed, _) = ParsedPacket::parse(&replies[1]).unwrap();
        let scb = parsed.scb.unwrap();
        assert_eq!(scb.ty, ScsType::Scs14);
        assert_eq!(scb.data, &[1]);
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn establish_secure_channel_fails_without_key_material_before_scs_11() {
        let mut acu = Acu::new(LoopbackPdTransport::new(), MockClock::new());
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(None);
        let mut rng = FixedRandom([0xA1; 8]);

        let err = acu
            .establish_secure_channel(0x05, &mut state, &mut keys, &mut rng)
            .unwrap_err();

        assert!(matches!(
            err,
            Error::SecureSession(crate::error::SecureSessionError::KeyUnavailable)
        ));
        assert!(!state.is_secure());
        assert!(acu.transport().writes.is_empty());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn receive_scs14_nak_failure_resets_secure_state() {
        let mut acu = Acu::new(VecTransport::new(), MockClock::new());
        let mut pd_driver = Pd::new(VecTransport::new(), MockClock::new(), 0x05, SecurePd)
            .with_secure_channel(
                PdSecureConfig { cuid: [0xC1; 8] },
                FixedPdKeys::scbk_d_only(),
            );
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_d_material()));
        let mut acu_rng = FixedRandom([0xA1; 8]);
        let mut pd_rng = FixedRandom([0xB2; 8]);

        acu.send_secure_challenge(0x05, &mut state, &mut keys, &mut acu_rng)
            .unwrap();
        acu.transport().shuffle_to(pd_driver.transport());
        assert!(pd_driver.poll_once_with_rng(&mut pd_rng).unwrap());
        pd_driver.transport().shuffle_to(acu.transport());
        acu.receive_secure_ccrypt(&mut state).unwrap();

        let failure = PacketBuilder::plain(
            Address::reply(0x05).unwrap(),
            ControlByte::new(state.next_sqn, CtrlFlags::USE_CRC),
            ReplyCode::Nak.as_byte(),
            Nak::simple(NakErrorCode::SecurityBlockTypeNotSupported)
                .encode()
                .unwrap(),
        )
        .encode()
        .unwrap();
        acu.transport().feed(&failure);

        let err = acu.receive_secure_rmac_i(&mut state).unwrap_err();

        assert!(matches!(err, Error::Nak { code: 0x05 }));
        assert!(!state.is_secure());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn receive_scs14_status_failure_resets_secure_state() {
        let mut acu = Acu::new(VecTransport::new(), MockClock::new());
        let mut pd_driver = Pd::new(VecTransport::new(), MockClock::new(), 0x05, SecurePd)
            .with_secure_channel(
                PdSecureConfig { cuid: [0xC1; 8] },
                FixedPdKeys::scbk_d_only(),
            );
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_d_material()));
        let mut acu_rng = FixedRandom([0xA1; 8]);
        let mut pd_rng = FixedRandom([0xB2; 8]);

        acu.send_secure_challenge(0x05, &mut state, &mut keys, &mut acu_rng)
            .unwrap();
        acu.transport().shuffle_to(pd_driver.transport());
        assert!(pd_driver.poll_once_with_rng(&mut pd_rng).unwrap());
        pd_driver.transport().shuffle_to(acu.transport());
        acu.receive_secure_ccrypt(&mut state).unwrap();

        let failure = PacketBuilder {
            addr: Address::reply(0x05).unwrap(),
            ctrl: ControlByte::new(state.next_sqn, CtrlFlags::USE_CRC | CtrlFlags::HAS_SCB),
            scb: Some(Scb::new(ScsType::Scs14, [0xff])),
            code: ReplyCode::RMacI.as_byte(),
            data: RMacI { r_mac_i: [0; 16] }.encode().unwrap(),
        }
        .encode()
        .unwrap();
        acu.transport().feed(&failure);

        let err = acu.receive_secure_rmac_i(&mut state).unwrap_err();

        assert!(matches!(
            err,
            Error::SecureSession(crate::error::SecureSessionError::BadCryptogram)
        ));
        assert!(!state.is_secure());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn exchange_uses_mac_only_secure_frames_after_handshake() {
        let mut acu = Acu::new(LoopbackPdTransport::new(), MockClock::new());
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_d_material()));
        let mut rng = FixedRandom([0xA1; 8]);

        acu.establish_secure_channel(0x05, &mut state, &mut keys, &mut rng)
            .unwrap();

        let outcome = acu
            .exchange(0x05, &mut state, &Command::Poll(Poll))
            .unwrap();
        assert_eq!(
            outcome,
            ExchangeOutcome::Reply(Reply::Ack(crate::reply::Ack))
        );
        assert_eq!(state.next_sqn.value(), 3);

        let (parsed, _) = ParsedPacket::parse(acu.transport().last_write()).unwrap();
        let scb = parsed.scb.unwrap();
        assert_eq!(scb.ty, ScsType::Scs15);
        assert!(parsed.data.is_empty());
        assert!(parsed.mac.is_some());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn exchange_encrypts_secure_data_frames_after_handshake() {
        let mut acu = Acu::new(LoopbackPdTransport::new(), MockClock::new());
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_d_material()));
        let mut rng = FixedRandom([0xA1; 8]);

        acu.establish_secure_channel(0x05, &mut state, &mut keys, &mut rng)
            .unwrap();

        let outcome = acu
            .exchange(0x05, &mut state, &Command::Id(Id::standard()))
            .unwrap();
        assert_eq!(
            outcome,
            ExchangeOutcome::Reply(Reply::PdId(PdId {
                vendor_oui: [0x00, 0x06, 0x8E],
                model: 0x12,
                version: 0x34,
                serial: 0xCAFE_BABE,
                firmware: [1, 2, 3],
            }))
        );
        assert_eq!(state.next_sqn.value(), 3);

        let (parsed, _) = ParsedPacket::parse(acu.transport().last_write()).unwrap();
        let scb = parsed.scb.unwrap();
        assert_eq!(scb.ty, ScsType::Scs17);
        assert_ne!(parsed.data, &[0x00]);
        assert!(parsed.mac.is_some());

        let (parsed, _) = ParsedPacket::parse(acu.transport().last_reply()).unwrap();
        let scb = parsed.scb.unwrap();
        assert_eq!(scb.ty, ScsType::Scs18);
        assert_ne!(
            parsed.data,
            &[
                0x00, 0x06, 0x8E, 0x12, 0x34, 0xBE, 0xBA, 0xFE, 0xCA, 0x01, 0x02, 0x03,
            ]
        );
        assert!(parsed.mac.is_some());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_exchange_retries_reuse_sealed_frame() {
        let mut acu = Acu::new(LoopbackPdTransport::new(), MockClock::new());
        acu.retry = RetryConfig {
            max_retries: 1,
            overall_budget_ms: 0,
        };
        let mut state = PdState::default();
        let mut keys = FixedAcuKeys(Some(scbk_d_material()));
        let mut rng = FixedRandom([0xA1; 8]);

        acu.establish_secure_channel(0x05, &mut state, &mut keys, &mut rng)
            .unwrap();

        let first_exchange_write = acu.transport().writes.len();
        acu.transport().drop_next_reply();
        let outcome = acu
            .exchange(0x05, &mut state, &Command::Poll(Poll))
            .unwrap();

        assert_eq!(
            outcome,
            ExchangeOutcome::Reply(Reply::Ack(crate::reply::Ack))
        );
        assert_eq!(state.next_sqn.value(), 3);
        let writes = &acu.transport().writes;
        assert_eq!(
            writes[first_exchange_write],
            writes[first_exchange_write + 1]
        );

        let outcome = acu
            .exchange(0x05, &mut state, &Command::Id(Id::standard()))
            .unwrap();

        assert!(matches!(outcome, ExchangeOutcome::Reply(Reply::PdId(_))));
        assert_eq!(state.next_sqn.value(), 1);
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_exchange_timeout_resets_secure_state() {
        let mut state = establish_secure_state();
        let mut acu = Acu::new(SilentTransport::new(), MockClock::new());
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };

        let outcome = acu
            .exchange(0x05, &mut state, &Command::Poll(Poll))
            .unwrap();

        assert_eq!(outcome, ExchangeOutcome::Timeout);
        assert!(!state.is_secure());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_exchange_offline_after_send_resets_secure_state() {
        let mut state = establish_secure_state();
        let clock = MockClock::new();
        let transport =
            SilentTransport::advancing(clock.clone(), crate::OFFLINE_THRESHOLD_MS as u64);
        let mut acu = Acu::new(transport, clock);
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };

        let outcome = acu
            .exchange(0x05, &mut state, &Command::Poll(Poll))
            .unwrap();

        assert_eq!(outcome, ExchangeOutcome::Offline);
        assert!(!state.is_secure());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn exchange_rejects_plaintext_reply_after_handshake() {
        let mut state = establish_secure_state();
        let mut transport = VecTransport::new();
        let plaintext_reply = PacketBuilder::plain(
            Address::reply(0x05).unwrap(),
            ControlByte::new(state.next_sqn, CtrlFlags::USE_CRC),
            ReplyCode::Ack.as_byte(),
            Vec::new(),
        )
        .encode()
        .unwrap();
        transport.feed(&plaintext_reply);
        let mut acu = Acu::new(transport, MockClock::new());
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };

        let err = acu
            .exchange(0x05, &mut state, &Command::Poll(Poll))
            .unwrap_err();

        assert!(matches!(
            err,
            Error::SecureSession(crate::error::SecureSessionError::NotSecure)
        ));
        assert!(!state.is_secure());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn exchange_rejects_wrong_direction_secure_reply_after_handshake() {
        let mut state = establish_secure_state();
        let mut transport = VecTransport::new();
        let wrong_direction_reply = PacketBuilder {
            addr: Address::reply(0x05).unwrap(),
            ctrl: ControlByte::new(state.next_sqn, CtrlFlags::USE_CRC | CtrlFlags::HAS_SCB),
            scb: Some(Scb::new(ScsType::Scs15, [])),
            code: ReplyCode::Ack.as_byte(),
            data: Vec::new(),
        }
        .encode_with_mac(|_| [0u8; crate::packet::MAC_LEN])
        .unwrap();
        transport.feed(&wrong_direction_reply);
        let mut acu = Acu::new(transport, MockClock::new());
        acu.retry = RetryConfig {
            max_retries: 0,
            overall_budget_ms: 0,
        };

        let err = acu
            .exchange(0x05, &mut state, &Command::Poll(Poll))
            .unwrap_err();

        assert!(matches!(err, Error::BadSecurityBlock(0x15)));
        assert!(!state.is_secure());
    }
}
