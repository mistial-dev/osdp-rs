//! PD (Peripheral Device) driver — receives commands from the ACU and
//! emits replies. A real PD also owns the SCS state on the slave side.
//!
//! This is currently a thin scaffold: the dispatcher wires up incoming
//! [`crate::command::Command`] values and delegates response generation to a
//! caller-supplied handler.

use crate::clock::Clock;
use crate::command::{Command, CommandCode};
use crate::error::Error;
use crate::packet::{Address, ControlByte, CtrlFlags, PacketBuilder, ParsedPacket, Sqn};
use crate::reply::Reply;
use crate::transport::Transport;
use alloc::vec::Vec;

#[cfg(feature = "secure-channel")]
use crate::command::{Chlng, SCrypt};
#[cfg(feature = "secure-channel")]
use crate::packet::{Scb, ScsType};
#[cfg(feature = "secure-channel")]
use crate::secure::{Disconnected, PdChallenged, Secure, Session, frame};

/// Trait for PD-side application logic. Each incoming command becomes a
/// method call; the handler returns the reply to emit.
pub trait PdHandler {
    /// Dispatch a fully-decoded command and return the reply payload.
    fn on_command(&mut self, command: &Command) -> Reply;

    /// Return the SCBK requested by the secure-channel handshake.
    ///
    /// OSDP v2.2 Annex D.1.3.1 uses `SEC_BLK_DATA[0]` on SCS_11 to select
    /// the current SCBK (`1`) or SCBK-D (`0`). Key ownership is application
    /// state, so the PD driver asks the handler instead of storing keys.
    #[cfg(feature = "secure-channel")]
    fn secure_channel_key(&mut self, _selection: PdSecureKey) -> Option<[u8; 16]> {
        None
    }

    /// Produce the PD random challenge `RND.B` for SCS_12.
    ///
    /// Annex D.1.3.2 requires the PD to generate this value. Tests may return
    /// deterministic bytes; production handlers should use their platform RNG.
    #[cfg(feature = "secure-channel")]
    fn secure_channel_random(&mut self) -> Option<[u8; 8]> {
        None
    }
}

/// Secure-channel key selector from SCS handshake `SEC_BLK_DATA[0]`.
#[cfg(feature = "secure-channel")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdSecureKey {
    /// Current SCBK selected by `SEC_BLK_DATA[0] == 1`.
    Scbk,
    /// Installation default SCBK-D selected by `SEC_BLK_DATA[0] == 0`.
    ScbkD,
}

#[cfg(feature = "secure-channel")]
impl PdSecureKey {
    fn from_scb_data(data: &[u8]) -> Result<Self, Error> {
        match data {
            [0] => Ok(Self::ScbkD),
            [1] => Ok(Self::Scbk),
            _ => Err(Error::MalformedPayload {
                code: 0x76,
                reason: "SCS handshake SEC_BLK_DATA must be exactly [0] or [1]",
            }),
        }
    }

    const fn as_scb_data(self) -> [u8; 1] {
        match self {
            Self::ScbkD => [0],
            Self::Scbk => [1],
        }
    }
}

/// Static secure-channel identity used by the PD handshake.
#[cfg(feature = "secure-channel")]
#[derive(Debug, Clone, Copy)]
pub struct PdSecureConfig {
    /// PD client identifier sent in `osdp_CCRYPT`.
    pub cuid: [u8; 8],
}

#[cfg(feature = "secure-channel")]
enum PdSecureState {
    Disconnected(Session<Disconnected>),
    Challenged {
        session: Session<PdChallenged>,
        key: PdSecureKey,
    },
    Secure(Session<Secure>),
}

/// PD driver.
pub struct Pd<T: Transport, C: Clock, H: PdHandler> {
    transport: T,
    #[allow(dead_code)]
    clock: C,
    /// PD's own bus address.
    pub address: u8,
    /// Whether to advertise CRC trailers in replies.
    pub use_crc: bool,
    handler: H,
    rx_buf: Vec<u8>,
    /// Last SQN we acted upon.
    last_sqn: Option<u8>,
    /// Last reply we sent (so we can repeat it on a duplicate SQN).
    last_reply: Option<Vec<u8>>,
    #[cfg(feature = "secure-channel")]
    secure_config: Option<PdSecureConfig>,
    #[cfg(feature = "secure-channel")]
    secure_state: Option<PdSecureState>,
}

impl<T: Transport, C: Clock, H: PdHandler> Pd<T, C, H> {
    /// New driver.
    pub fn new(transport: T, clock: C, address: u8, handler: H) -> Self {
        Self {
            transport,
            clock,
            address,
            use_crc: true,
            handler,
            rx_buf: Vec::with_capacity(crate::MAX_BUS_PACKET),
            last_sqn: None,
            last_reply: None,
            #[cfg(feature = "secure-channel")]
            secure_config: None,
            #[cfg(feature = "secure-channel")]
            secure_state: None,
        }
    }

    /// Enable PD-side secure-channel handshake handling.
    #[cfg(feature = "secure-channel")]
    pub fn with_secure_channel(mut self, config: PdSecureConfig) -> Self {
        self.secure_config = Some(config);
        self.secure_state = None;
        self
    }

    /// Borrow the underlying transport.
    pub fn transport(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Drain whatever bytes the transport has, dispatch the next complete
    /// command, and reply on the wire if there is one.
    ///
    /// Returns `Ok(true)` if a packet was processed, `Ok(false)` if more
    /// bytes are required.
    pub fn poll_once(&mut self) -> Result<bool, Error> {
        let mut tmp = [0u8; 64];
        let n = self.transport.read(&mut tmp)?;
        if n > 0 {
            self.rx_buf.extend_from_slice(&tmp[..n]);
        }

        while let Some(som_pos) = self.rx_buf.iter().position(|&b| b == crate::SOM) {
            self.rx_buf.drain(..som_pos);
            match ParsedPacket::parse(&self.rx_buf) {
                Ok((parsed, used)) => {
                    let pd_addr = parsed.addr.pd_addr();
                    if pd_addr != self.address && !parsed.addr.is_broadcast() {
                        // Not for us — drop and resume.
                        self.rx_buf.drain(..used);
                        continue;
                    }
                    let code = CommandCode::from_byte(parsed.code)?;
                    let sqn = parsed.ctrl.sqn.value();
                    let cmd_data = parsed.data.to_vec();
                    #[cfg(feature = "secure-channel")]
                    let scb = parsed.scb.map(Scb::from);
                    #[cfg(feature = "secure-channel")]
                    let raw_packet = self.rx_buf[..used].to_vec();
                    let used_len = used;
                    self.rx_buf.drain(..used_len);

                    if Some(sqn) == self.last_sqn {
                        // ACU is asking for a reply repeat.
                        if let Some(reply) = &self.last_reply {
                            let r = reply.clone();
                            self.transport.write_all(&r)?;
                        }
                        return Ok(true);
                    }

                    #[cfg(feature = "secure-channel")]
                    if let Some(bytes) =
                        self.handle_secure_handshake(sqn, scb.as_ref(), code, &cmd_data)?
                    {
                        self.transport.write_all(&bytes)?;
                        self.last_sqn = Some(sqn);
                        self.last_reply = Some(bytes);
                        let _ = self.clock.now_ms();
                        return Ok(true);
                    }

                    #[cfg(feature = "secure-channel")]
                    let cmd_data = {
                        let mut data = cmd_data;
                        if self.is_secure_session_established() {
                            match scb.as_ref().map(|scb| scb.ty) {
                                Some(ScsType::Scs15 | ScsType::Scs17) => {
                                    data = self.unseal_secure_command(&raw_packet)?;
                                }
                                _ => {
                                    // OSDP v2.2 Annex D.1.4 requires all
                                    // post-SCS-CS messages from the ACU to
                                    // carry SCS_15 or SCS_17. Anything else
                                    // is unauthenticated traffic and must not
                                    // reach the application handler.
                                    return Err(Error::SecureSession(
                                        crate::error::SecureSessionError::NotSecure,
                                    ));
                                }
                            }
                        }
                        data
                    };

                    let command = Command::decode(code, &cmd_data)?;
                    let reply = self.handler.on_command(&command);
                    #[cfg(feature = "secure-channel")]
                    let bytes = self.encode_reply_secure_if_established(sqn, &reply)?;
                    #[cfg(not(feature = "secure-channel"))]
                    let bytes = self.encode_reply(sqn, &reply)?;
                    self.transport.write_all(&bytes)?;
                    self.last_sqn = Some(sqn);
                    self.last_reply = Some(bytes);
                    let _ = self.clock.now_ms();
                    return Ok(true);
                }
                Err(Error::Truncated { .. }) => return Ok(false),
                Err(Error::BadSom(_)) => {
                    self.rx_buf.remove(0);
                    continue;
                }
                Err(other) => return Err(other),
            }
        }

        Ok(false)
    }

    fn encode_reply(&self, sqn: u8, reply: &Reply) -> Result<Vec<u8>, Error> {
        let addr = Address::reply(self.address)?;
        let ctrl = ControlByte::new(
            Sqn::new(sqn)?,
            if self.use_crc {
                CtrlFlags::USE_CRC
            } else {
                CtrlFlags::empty()
            },
        );
        let data = reply.encode_data()?;
        PacketBuilder::plain(addr, ctrl, reply.code().as_byte(), data).encode()
    }

    #[cfg(feature = "secure-channel")]
    fn encode_reply_secure_if_established(
        &mut self,
        sqn: u8,
        reply: &Reply,
    ) -> Result<Vec<u8>, Error> {
        let state = match self.secure_state.take() {
            Some(PdSecureState::Secure(session)) => session,
            Some(state) => {
                self.secure_state = Some(state);
                return self.encode_reply(sqn, reply);
            }
            None => return self.encode_reply(sqn, reply),
        };
        let mut session = state;
        let data = reply.encode_data()?;
        let bytes = frame::seal(
            &mut session,
            Address::reply(self.address)?,
            Sqn::new(sqn)?,
            frame::Direction::PdToAcu,
            !data.is_empty(),
            reply.code().as_byte(),
            &data,
        )?;
        self.secure_state = Some(PdSecureState::Secure(session));
        Ok(bytes)
    }

    #[cfg(feature = "secure-channel")]
    fn encode_reply_with_scb(&self, sqn: u8, scb: Scb, reply: &Reply) -> Result<Vec<u8>, Error> {
        let addr = Address::reply(self.address)?;
        let ctrl = ControlByte::new(
            Sqn::new(sqn)?,
            if self.use_crc {
                CtrlFlags::USE_CRC | CtrlFlags::HAS_SCB
            } else {
                CtrlFlags::HAS_SCB
            },
        );
        let data = reply.encode_data()?;
        PacketBuilder {
            addr,
            ctrl,
            scb: Some(scb),
            code: reply.code().as_byte(),
            data,
        }
        .encode()
    }

    #[cfg(feature = "secure-channel")]
    fn handle_secure_handshake(
        &mut self,
        sqn: u8,
        scb: Option<&Scb>,
        code: CommandCode,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        match (scb.map(|scb| scb.ty), code) {
            (Some(ScsType::Scs11), CommandCode::Chlng) => {
                let Some(config) = self.secure_config else {
                    return Ok(None);
                };
                let key_selection = PdSecureKey::from_scb_data(&scb.unwrap().data)?;
                let Some(scbk) = self.handler.secure_channel_key(key_selection) else {
                    return Err(Error::MalformedPayload {
                        code: 0x76,
                        reason: "secure-channel key unavailable",
                    });
                };
                let Some(rnd_b) = self.handler.secure_channel_random() else {
                    return Err(Error::MalformedPayload {
                        code: 0x76,
                        reason: "secure-channel random unavailable",
                    });
                };
                let chlng = Chlng::decode(data)?;
                let _ = self.secure_state.take();
                let disconnected = Session::new(scbk);
                let challenged = disconnected.receive_challenge(chlng.rnd_a, config.cuid, rnd_b);
                let ccrypt = challenged.ccrypt();
                self.secure_state = Some(PdSecureState::Challenged {
                    session: challenged,
                    key: key_selection,
                });
                let bytes = self.encode_reply_with_scb(
                    sqn,
                    Scb::new(ScsType::Scs12, key_selection.as_scb_data()),
                    &Reply::CCrypt(ccrypt),
                )?;
                Ok(Some(bytes))
            }
            (Some(ScsType::Scs13), CommandCode::SCrypt) => {
                if self.secure_config.is_none() {
                    return Ok(None);
                };
                let key_selection = PdSecureKey::from_scb_data(&scb.unwrap().data)?;
                let scrypt = SCrypt::decode(data)?;
                let state = self.secure_state.take();
                let challenged = match state {
                    Some(PdSecureState::Challenged { session, key }) if key == key_selection => {
                        session
                    }
                    Some(PdSecureState::Challenged { session, .. }) => {
                        self.secure_state = Some(PdSecureState::Disconnected(session.reset()));
                        return Err(Error::SecureSession(
                            crate::error::SecureSessionError::BadCryptogram,
                        ));
                    }
                    Some(PdSecureState::Disconnected(session)) => {
                        self.secure_state = Some(PdSecureState::Disconnected(session));
                        return Ok(None);
                    }
                    Some(PdSecureState::Secure(session)) => {
                        self.secure_state = Some(PdSecureState::Secure(session));
                        return Ok(None);
                    }
                    None => return Ok(None),
                };
                match challenged.receive_scrypt(&scrypt) {
                    Ok((secure, rmac_i)) => {
                        self.secure_state = Some(PdSecureState::Secure(secure));
                        let bytes = self.encode_reply_with_scb(
                            sqn,
                            Scb::new(ScsType::Scs14, key_selection.as_scb_data()),
                            &Reply::RMacI(rmac_i),
                        )?;
                        Ok(Some(bytes))
                    }
                    Err((session, err)) => {
                        self.secure_state = Some(PdSecureState::Disconnected(session));
                        Err(Error::from(err))
                    }
                }
            }
            _ => Ok(None),
        }
    }

    #[cfg(feature = "secure-channel")]
    fn is_secure_session_established(&self) -> bool {
        matches!(self.secure_state, Some(PdSecureState::Secure(_)))
    }

    #[cfg(feature = "secure-channel")]
    fn unseal_secure_command(&mut self, raw: &[u8]) -> Result<Vec<u8>, Error> {
        let state = match self.secure_state.take() {
            Some(PdSecureState::Secure(session)) => session,
            Some(state) => {
                self.secure_state = Some(state);
                return Err(Error::SecureSession(
                    crate::error::SecureSessionError::NotSecure,
                ));
            }
            None => {
                return Err(Error::SecureSession(
                    crate::error::SecureSessionError::NotSecure,
                ));
            }
        };
        let (parsed, _) = ParsedPacket::parse(raw)?;
        // OSDP v2.2 Annex D.6.1 unwrap requires the receiver to validate the
        // secure-message MAC before consuming DATA, then decrypt SCS_17 DATA.
        // On failure, Annex D.1.2 treats synchronization as lost; `unseal`
        // returns the reset session so the PD can require a fresh SCS-CS flow.
        match frame::unseal(state, &parsed, raw) {
            Ok((session, plaintext)) => {
                self.secure_state = Some(PdSecureState::Secure(session));
                Ok(plaintext)
            }
            Err(err) => {
                self.secure_state = Some(PdSecureState::Disconnected(err.session));
                Err(err.error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::command::{Command, Id};
    use crate::reply::{Ack, PdId, Reply, ReplyCode};
    use crate::transport::VecTransport;

    #[cfg(feature = "secure-channel")]
    use crate::command::SCrypt;
    #[cfg(feature = "secure-channel")]
    use crate::reply::{CCrypt, RMacI};
    #[cfg(feature = "secure-channel")]
    use crate::secure::frame::{Direction, seal, unseal};
    #[cfg(feature = "secure-channel")]
    use crate::secure::{SCBK_D, Secure, Session};
    #[cfg(feature = "secure-channel")]
    use core::cell::Cell;
    #[cfg(feature = "secure-channel")]
    use std::rc::Rc;

    #[cfg(feature = "secure-channel")]
    const TEST_SCBK: [u8; 16] = [0xA5; 16];
    #[cfg(feature = "secure-channel")]
    const TEST_RND_B: [u8; 8] = [0xB2; 8];

    struct AlwaysAck;
    impl PdHandler for AlwaysAck {
        fn on_command(&mut self, _command: &Command) -> Reply {
            Reply::Ack(Ack)
        }

        #[cfg(feature = "secure-channel")]
        fn secure_channel_key(&mut self, selection: PdSecureKey) -> Option<[u8; 16]> {
            match selection {
                PdSecureKey::Scbk => Some(TEST_SCBK),
                PdSecureKey::ScbkD => Some(SCBK_D),
            }
        }

        #[cfg(feature = "secure-channel")]
        fn secure_channel_random(&mut self) -> Option<[u8; 8]> {
            Some(TEST_RND_B)
        }
    }

    #[test]
    fn dispatches_poll_to_ack() {
        let clock = MockClock::new();
        let mut transport = VecTransport::new();
        // Encode a POLL ourselves and feed it to the PD's incoming queue.
        let bytes = PacketBuilder::plain(
            Address::pd(0x05).unwrap(),
            ControlByte::new(Sqn::new(1).unwrap(), CtrlFlags::USE_CRC),
            CommandCode::Poll.as_byte(),
            Vec::new(),
        )
        .encode()
        .unwrap();
        transport.feed(&bytes);
        let mut pd = Pd::new(transport, clock, 0x05, AlwaysAck);
        assert!(pd.poll_once().unwrap());
        let reply_bytes: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed, _) = ParsedPacket::parse(&reply_bytes).unwrap();
        assert_eq!(parsed.code, 0x40);
        assert!(parsed.addr.is_reply());
    }

    #[cfg(feature = "secure-channel")]
    fn secure_config() -> PdSecureConfig {
        PdSecureConfig { cuid: [0xC1; 8] }
    }

    #[cfg(feature = "secure-channel")]
    fn secure_command_packet(sqn: u8, scs: ScsType, command: &Command) -> Result<Vec<u8>, Error> {
        secure_command_packet_with_key(sqn, scs, PdSecureKey::Scbk, command)
    }

    #[cfg(feature = "secure-channel")]
    fn secure_command_packet_with_key(
        sqn: u8,
        scs: ScsType,
        key: PdSecureKey,
        command: &Command,
    ) -> Result<Vec<u8>, Error> {
        PacketBuilder {
            addr: Address::pd(0x05)?,
            ctrl: ControlByte::new(Sqn::new(sqn)?, CtrlFlags::USE_CRC | CtrlFlags::HAS_SCB),
            scb: Some(Scb::new(scs, key.as_scb_data())),
            code: command.code().as_byte(),
            data: command.encode_data()?,
        }
        .encode()
    }

    #[cfg(feature = "secure-channel")]
    fn secure_pd_with_acu<H: PdHandler>(
        handler: H,
    ) -> (Pd<VecTransport, MockClock, H>, Session<Secure>) {
        let config = secure_config();
        let rnd_a = [0xA1; 8];
        let acu = Session::<Disconnected>::new(TEST_SCBK).challenge(rnd_a);
        let mut transport = VecTransport::new();
        transport.feed(
            &secure_command_packet(1, ScsType::Scs11, &Command::Chlng(Chlng::new(rnd_a))).unwrap(),
        );
        let mut pd =
            Pd::new(transport, MockClock::new(), 0x05, handler).with_secure_channel(config);
        assert!(pd.poll_once().unwrap());
        let ccrypt_reply: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed_ccrypt, _) = ParsedPacket::parse(&ccrypt_reply).unwrap();
        let ccrypt = CCrypt::decode(parsed_ccrypt.data).unwrap();
        let acu = acu.receive_ccrypt(&ccrypt).unwrap();

        let scrypt_packet = secure_command_packet(
            2,
            ScsType::Scs13,
            &Command::SCrypt(SCrypt::new(acu.server_cryptogram())),
        )
        .unwrap();
        pd.transport().feed(&scrypt_packet);
        assert!(pd.poll_once().unwrap());
        pd.transport().outgoing.clear();
        let rmac_i = acu.initial_rmac();
        let acu = acu.confirm_rmac_i(&rmac_i).unwrap();
        (pd, acu)
    }

    #[cfg(feature = "secure-channel")]
    struct RecordingHandler {
        called: Rc<Cell<bool>>,
    }

    #[cfg(feature = "secure-channel")]
    impl PdHandler for RecordingHandler {
        fn on_command(&mut self, _command: &Command) -> Reply {
            self.called.set(true);
            Reply::Ack(Ack)
        }

        fn secure_channel_key(&mut self, selection: PdSecureKey) -> Option<[u8; 16]> {
            match selection {
                PdSecureKey::Scbk => Some(TEST_SCBK),
                PdSecureKey::ScbkD => Some(SCBK_D),
            }
        }

        fn secure_channel_random(&mut self) -> Option<[u8; 8]> {
            Some(TEST_RND_B)
        }
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_challenge_replies_with_ccrypt() {
        let config = secure_config();
        let rnd_a = [0xA1; 8];
        let bytes =
            secure_command_packet(1, ScsType::Scs11, &Command::Chlng(Chlng::new(rnd_a))).unwrap();
        let mut transport = VecTransport::new();
        transport.feed(&bytes);
        let mut pd =
            Pd::new(transport, MockClock::new(), 0x05, AlwaysAck).with_secure_channel(config);

        assert!(pd.poll_once().unwrap());
        let reply_bytes: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed, _) = ParsedPacket::parse(&reply_bytes).unwrap();
        assert_eq!(parsed.scb.unwrap().ty, ScsType::Scs12);
        assert_eq!(parsed.scb.unwrap().data, &[1]);
        assert_eq!(parsed.code, 0x76);

        let ccrypt = CCrypt::decode(parsed.data).unwrap();
        let expected = Session::<Disconnected>::new(TEST_SCBK)
            .receive_challenge(rnd_a, config.cuid, TEST_RND_B)
            .ccrypt();
        assert_eq!(ccrypt, expected);
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_challenge_can_select_default_scbk() {
        let config = secure_config();
        let rnd_a = [0xA1; 8];
        let bytes = secure_command_packet_with_key(
            1,
            ScsType::Scs11,
            PdSecureKey::ScbkD,
            &Command::Chlng(Chlng::new(rnd_a)),
        )
        .unwrap();
        let mut transport = VecTransport::new();
        transport.feed(&bytes);
        let mut pd =
            Pd::new(transport, MockClock::new(), 0x05, AlwaysAck).with_secure_channel(config);

        assert!(pd.poll_once().unwrap());
        let reply_bytes: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed, _) = ParsedPacket::parse(&reply_bytes).unwrap();
        assert_eq!(parsed.scb.unwrap().ty, ScsType::Scs12);
        assert_eq!(parsed.scb.unwrap().data, &[0]);

        let ccrypt = CCrypt::decode(parsed.data).unwrap();
        let expected = Session::<Disconnected>::new(SCBK_D)
            .receive_challenge(rnd_a, config.cuid, TEST_RND_B)
            .ccrypt();
        assert_eq!(ccrypt, expected);
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_scrypt_replies_with_rmac_i() {
        let config = secure_config();
        let rnd_a = [0xA1; 8];
        let acu = Session::<Disconnected>::new(TEST_SCBK).challenge(rnd_a);

        let chlng =
            secure_command_packet(1, ScsType::Scs11, &Command::Chlng(Chlng::new(rnd_a))).unwrap();
        let mut transport = VecTransport::new();
        transport.feed(&chlng);
        let mut pd =
            Pd::new(transport, MockClock::new(), 0x05, AlwaysAck).with_secure_channel(config);
        assert!(pd.poll_once().unwrap());
        let ccrypt_reply: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed_ccrypt, _) = ParsedPacket::parse(&ccrypt_reply).unwrap();
        let ccrypt = CCrypt::decode(parsed_ccrypt.data).unwrap();
        let acu = acu.receive_ccrypt(&ccrypt).unwrap();

        let scrypt = SCrypt::new(acu.server_cryptogram());
        let scrypt_packet =
            secure_command_packet(2, ScsType::Scs13, &Command::SCrypt(scrypt)).unwrap();
        pd.transport().feed(&scrypt_packet);
        assert!(pd.poll_once().unwrap());

        let rmac_reply: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed_rmac, _) = ParsedPacket::parse(&rmac_reply).unwrap();
        assert_eq!(parsed_rmac.scb.unwrap().ty, ScsType::Scs14);
        assert_eq!(parsed_rmac.scb.unwrap().data, &[1]);
        assert_eq!(parsed_rmac.code, 0x78);

        let rmac = RMacI::decode(parsed_rmac.data).unwrap();
        assert_eq!(rmac.r_mac_i, acu.initial_rmac());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_handshake_bypasses_pdhandler() {
        struct PanicHandler;
        impl PdHandler for PanicHandler {
            fn on_command(&mut self, _command: &Command) -> Reply {
                panic!("secure handshake must not reach PdHandler")
            }

            fn secure_channel_key(&mut self, selection: PdSecureKey) -> Option<[u8; 16]> {
                match selection {
                    PdSecureKey::Scbk => Some(TEST_SCBK),
                    PdSecureKey::ScbkD => Some(SCBK_D),
                }
            }

            fn secure_channel_random(&mut self) -> Option<[u8; 8]> {
                Some(TEST_RND_B)
            }
        }

        let config = secure_config();
        let bytes =
            secure_command_packet(1, ScsType::Scs11, &Command::Chlng(Chlng::new([0xA1; 8])))
                .unwrap();
        let mut transport = VecTransport::new();
        transport.feed(&bytes);
        let mut pd =
            Pd::new(transport, MockClock::new(), 0x05, PanicHandler).with_secure_channel(config);

        assert!(pd.poll_once().unwrap());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_encrypted_command_is_unsealed_before_dispatch() {
        struct ExpectId;
        impl PdHandler for ExpectId {
            fn on_command(&mut self, command: &Command) -> Reply {
                assert!(matches!(command, Command::Id(Id { reserved: 0 })));
                Reply::Ack(Ack)
            }

            fn secure_channel_key(&mut self, selection: PdSecureKey) -> Option<[u8; 16]> {
                match selection {
                    PdSecureKey::Scbk => Some(TEST_SCBK),
                    PdSecureKey::ScbkD => Some(SCBK_D),
                }
            }

            fn secure_channel_random(&mut self) -> Option<[u8; 8]> {
                Some(TEST_RND_B)
            }
        }

        let config = secure_config();
        let rnd_a = [0xA1; 8];
        let acu = Session::<Disconnected>::new(TEST_SCBK).challenge(rnd_a);
        let mut transport = VecTransport::new();
        transport.feed(
            &secure_command_packet(1, ScsType::Scs11, &Command::Chlng(Chlng::new(rnd_a))).unwrap(),
        );
        let mut pd =
            Pd::new(transport, MockClock::new(), 0x05, ExpectId).with_secure_channel(config);
        assert!(pd.poll_once().unwrap());
        let ccrypt_reply: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed_ccrypt, _) = ParsedPacket::parse(&ccrypt_reply).unwrap();
        let ccrypt = CCrypt::decode(parsed_ccrypt.data).unwrap();
        let acu = acu.receive_ccrypt(&ccrypt).unwrap();

        let scrypt_packet = secure_command_packet(
            2,
            ScsType::Scs13,
            &Command::SCrypt(SCrypt::new(acu.server_cryptogram())),
        )
        .unwrap();
        pd.transport().feed(&scrypt_packet);
        assert!(pd.poll_once().unwrap());
        pd.transport().outgoing.clear();
        let rmac_i = acu.initial_rmac();
        let mut acu = acu.confirm_rmac_i(&rmac_i).unwrap();

        let secure_id = seal(
            &mut acu,
            Address::pd(0x05).unwrap(),
            Sqn::new(3).unwrap(),
            Direction::AcuToPd,
            true,
            CommandCode::Id.as_byte(),
            &Id::standard().encode().unwrap(),
        )
        .unwrap();
        pd.transport().feed(&secure_id);

        assert!(pd.poll_once().unwrap());
        let reply_bytes: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed_reply, _) = ParsedPacket::parse(&reply_bytes).unwrap();
        assert_eq!(parsed_reply.scb.unwrap().ty, ScsType::Scs16);
        let (_acu, plaintext) = unseal(acu, &parsed_reply, &reply_bytes).unwrap();
        assert!(plaintext.is_empty());
        let reply =
            Reply::decode(ReplyCode::from_byte(parsed_reply.code).unwrap(), &plaintext).unwrap();
        assert!(matches!(reply, Reply::Ack(_)));
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_reply_data_is_encrypted_and_mac_protected() {
        struct IdReply;
        impl PdHandler for IdReply {
            fn on_command(&mut self, command: &Command) -> Reply {
                assert!(matches!(command, Command::Id(Id { reserved: 0 })));
                Reply::PdId(PdId {
                    vendor_oui: [0x00, 0x06, 0x8E],
                    model: 0x12,
                    version: 0x34,
                    serial: 0xCAFE_BABE,
                    firmware: [1, 2, 3],
                })
            }

            fn secure_channel_key(&mut self, selection: PdSecureKey) -> Option<[u8; 16]> {
                match selection {
                    PdSecureKey::Scbk => Some(TEST_SCBK),
                    PdSecureKey::ScbkD => Some(SCBK_D),
                }
            }

            fn secure_channel_random(&mut self) -> Option<[u8; 8]> {
                Some(TEST_RND_B)
            }
        }

        let config = secure_config();
        let rnd_a = [0xA1; 8];
        let acu = Session::<Disconnected>::new(TEST_SCBK).challenge(rnd_a);
        let mut transport = VecTransport::new();
        transport.feed(
            &secure_command_packet(1, ScsType::Scs11, &Command::Chlng(Chlng::new(rnd_a))).unwrap(),
        );
        let mut pd =
            Pd::new(transport, MockClock::new(), 0x05, IdReply).with_secure_channel(config);
        assert!(pd.poll_once().unwrap());
        let ccrypt_reply: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed_ccrypt, _) = ParsedPacket::parse(&ccrypt_reply).unwrap();
        let ccrypt = CCrypt::decode(parsed_ccrypt.data).unwrap();
        let acu = acu.receive_ccrypt(&ccrypt).unwrap();

        let scrypt_packet = secure_command_packet(
            2,
            ScsType::Scs13,
            &Command::SCrypt(SCrypt::new(acu.server_cryptogram())),
        )
        .unwrap();
        pd.transport().feed(&scrypt_packet);
        assert!(pd.poll_once().unwrap());
        pd.transport().outgoing.clear();
        let rmac_i = acu.initial_rmac();
        let mut acu: Session<Secure> = acu.confirm_rmac_i(&rmac_i).unwrap();

        let secure_id = seal(
            &mut acu,
            Address::pd(0x05).unwrap(),
            Sqn::new(3).unwrap(),
            Direction::AcuToPd,
            true,
            CommandCode::Id.as_byte(),
            &Id::standard().encode().unwrap(),
        )
        .unwrap();
        pd.transport().feed(&secure_id);
        assert!(pd.poll_once().unwrap());

        let reply_bytes: Vec<u8> = pd.transport().outgoing.drain(..).collect();
        let (parsed_reply, _) = ParsedPacket::parse(&reply_bytes).unwrap();
        assert_eq!(parsed_reply.scb.unwrap().ty, ScsType::Scs18);
        let expected_plaintext = PdId {
            vendor_oui: [0x00, 0x06, 0x8E],
            model: 0x12,
            version: 0x34,
            serial: 0xCAFE_BABE,
            firmware: [1, 2, 3],
        }
        .encode()
        .unwrap();
        assert_ne!(parsed_reply.data, expected_plaintext.as_slice());

        let (acu, plaintext) = unseal(acu, &parsed_reply, &reply_bytes).unwrap();
        let reply =
            Reply::decode(ReplyCode::from_byte(parsed_reply.code).unwrap(), &plaintext).unwrap();
        assert!(matches!(
            reply,
            Reply::PdId(PdId {
                vendor_oui: [0x00, 0x06, 0x8E],
                serial: 0xCAFE_BABE,
                ..
            })
        ));
        let _ = acu;
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_session_rejects_plaintext_command_without_dispatch() {
        let called = Rc::new(Cell::new(false));
        let (mut pd, _acu) = secure_pd_with_acu(RecordingHandler {
            called: called.clone(),
        });
        let plaintext_poll = PacketBuilder::plain(
            Address::pd(0x05).unwrap(),
            ControlByte::new(Sqn::new(3).unwrap(), CtrlFlags::USE_CRC),
            CommandCode::Poll.as_byte(),
            Vec::new(),
        )
        .encode()
        .unwrap();
        pd.transport().feed(&plaintext_poll);

        let err = pd.poll_once().unwrap_err();
        assert!(matches!(
            err,
            Error::SecureSession(crate::error::SecureSessionError::NotSecure)
        ));
        assert!(!called.get());
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_session_rejects_reply_direction_scb_without_dispatch() {
        let called = Rc::new(Cell::new(false));
        let (mut pd, mut acu) = secure_pd_with_acu(RecordingHandler {
            called: called.clone(),
        });
        let wrong_direction_poll = seal(
            &mut acu,
            Address::pd(0x05).unwrap(),
            Sqn::new(3).unwrap(),
            Direction::PdToAcu,
            false,
            CommandCode::Poll.as_byte(),
            &[],
        )
        .unwrap();
        pd.transport().feed(&wrong_direction_poll);

        let err = pd.poll_once().unwrap_err();
        assert!(matches!(
            err,
            Error::SecureSession(crate::error::SecureSessionError::NotSecure)
        ));
        assert!(!called.get());
    }
}
