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
use crate::secure::{Disconnected, PdChallenged, Secure, Session};

/// Trait for PD-side application logic. Each incoming command becomes a
/// method call; the handler returns the reply to emit.
pub trait PdHandler {
    /// Dispatch a fully-decoded command and return the reply payload.
    fn on_command(&mut self, command: &Command) -> Reply;
}

/// Static secure-channel material used by the PD handshake scaffold.
#[cfg(feature = "secure-channel")]
#[derive(Debug, Clone, Copy)]
pub struct PdSecureConfig {
    /// Secure Channel Base Key selected by the caller.
    pub scbk: [u8; 16],
    /// PD client identifier sent in `osdp_CCRYPT`.
    pub cuid: [u8; 8],
    /// PD random number sent in `osdp_CCRYPT`.
    pub rnd_b: [u8; 8],
}

#[cfg(feature = "secure-channel")]
enum PdSecureState {
    Disconnected(Session<Disconnected>),
    Challenged(Session<PdChallenged>),
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
        self.secure_state = Some(PdSecureState::Disconnected(Session::new(config.scbk)));
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
                    let scb_ty = parsed.scb.map(|scb| scb.ty);
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
                        self.handle_secure_handshake(sqn, scb_ty, code, &cmd_data)?
                    {
                        self.transport.write_all(&bytes)?;
                        self.last_sqn = Some(sqn);
                        self.last_reply = Some(bytes);
                        let _ = self.clock.now_ms();
                        return Ok(true);
                    }

                    let command = Command::decode(code, &cmd_data)?;
                    let reply = self.handler.on_command(&command);
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
        scb_ty: Option<ScsType>,
        code: CommandCode,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        match (scb_ty, code) {
            (Some(ScsType::Scs11), CommandCode::Chlng) => {
                let Some(config) = self.secure_config else {
                    return Ok(None);
                };
                let chlng = Chlng::decode(data)?;
                let state = self
                    .secure_state
                    .take()
                    .unwrap_or_else(|| PdSecureState::Disconnected(Session::new(config.scbk)));
                let disconnected = match state {
                    PdSecureState::Disconnected(session) => session,
                    PdSecureState::Challenged(session) => session.reset(),
                    PdSecureState::Secure(session) => session.reset(),
                };
                let challenged =
                    disconnected.receive_challenge(chlng.rnd_a, config.cuid, config.rnd_b);
                let ccrypt = challenged.ccrypt();
                self.secure_state = Some(PdSecureState::Challenged(challenged));
                let bytes = self.encode_reply_with_scb(
                    sqn,
                    Scb::new(ScsType::Scs12, []),
                    &Reply::CCrypt(ccrypt),
                )?;
                Ok(Some(bytes))
            }
            (Some(ScsType::Scs13), CommandCode::SCrypt) => {
                let Some(config) = self.secure_config else {
                    return Ok(None);
                };
                let scrypt = SCrypt::decode(data)?;
                let state = self
                    .secure_state
                    .take()
                    .unwrap_or_else(|| PdSecureState::Disconnected(Session::new(config.scbk)));
                let challenged = match state {
                    PdSecureState::Challenged(session) => session,
                    PdSecureState::Disconnected(session) => {
                        self.secure_state = Some(PdSecureState::Disconnected(session));
                        return Ok(None);
                    }
                    PdSecureState::Secure(session) => {
                        self.secure_state = Some(PdSecureState::Secure(session));
                        return Ok(None);
                    }
                };
                match challenged.receive_scrypt(&scrypt) {
                    Ok((secure, rmac_i)) => {
                        self.secure_state = Some(PdSecureState::Secure(secure));
                        let bytes = self.encode_reply_with_scb(
                            sqn,
                            Scb::new(ScsType::Scs14, []),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::command::Command;
    use crate::reply::{Ack, Reply};
    use crate::transport::VecTransport;

    #[cfg(feature = "secure-channel")]
    use crate::command::SCrypt;
    #[cfg(feature = "secure-channel")]
    use crate::reply::{CCrypt, RMacI};
    #[cfg(feature = "secure-channel")]
    use crate::secure::{SCBK_D, Session};

    struct AlwaysAck;
    impl PdHandler for AlwaysAck {
        fn on_command(&mut self, _command: &Command) -> Reply {
            Reply::Ack(Ack)
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
        PdSecureConfig {
            scbk: SCBK_D,
            cuid: [0xC1; 8],
            rnd_b: [0xB2; 8],
        }
    }

    #[cfg(feature = "secure-channel")]
    fn secure_command_packet(sqn: u8, scs: ScsType, command: &Command) -> Result<Vec<u8>, Error> {
        PacketBuilder {
            addr: Address::pd(0x05)?,
            ctrl: ControlByte::new(Sqn::new(sqn)?, CtrlFlags::USE_CRC | CtrlFlags::HAS_SCB),
            scb: Some(Scb::new(scs, [])),
            code: command.code().as_byte(),
            data: command.encode_data()?,
        }
        .encode()
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
        assert_eq!(parsed.code, 0x76);

        let ccrypt = CCrypt::decode(parsed.data).unwrap();
        let expected = Session::<Disconnected>::new(config.scbk)
            .receive_challenge(rnd_a, config.cuid, config.rnd_b)
            .ccrypt();
        assert_eq!(ccrypt, expected);
    }

    #[cfg(feature = "secure-channel")]
    #[test]
    fn secure_scrypt_replies_with_rmac_i() {
        let config = secure_config();
        let rnd_a = [0xA1; 8];
        let acu = Session::<Disconnected>::new(config.scbk).challenge(rnd_a);

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
}
