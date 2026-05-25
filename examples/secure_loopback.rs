//! Secure loopback example: an ACU establishes SCS-CS with an in-memory PD,
//! then performs MAC-only and encrypted secure exchanges.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example secure_loopback --features secure-channel
//! ```

use osdp::Error;
use osdp::clock::SystemClock;
use osdp::command::{Command, Id, Poll};
use osdp::driver::acu::{Acu, AcuSecureKey, AcuSecureKeyMaterial, AcuSecureKeyProvider, PdState};
use osdp::driver::pd::{Pd, PdHandler, PdSecureConfig, PdSecureKey};
use osdp::reply::{Ack, PdId, Reply};
use osdp::secure::{SCBK_D, SecureRandom};
use osdp::transport::{Transport, VecTransport};
use std::collections::VecDeque;

struct DemoPd;

struct DemoAcuKeys;

struct FixedRandom([u8; 8]);

impl SecureRandom for FixedRandom {
    fn fill_secure_random(&mut self, out: &mut [u8]) -> osdp::error::Result<()> {
        out.copy_from_slice(&self.0);
        Ok(())
    }
}

impl PdHandler for DemoPd {
    fn on_command(&mut self, command: &Command) -> Reply {
        match command {
            Command::Id(_) => Reply::PdId(PdId {
                vendor_oui: [0x00, 0x06, 0x8E],
                model: 0x12,
                version: 0x34,
                serial: 0xCAFE_BABE,
                firmware: [1, 2, 3],
            }),
            _ => Reply::Ack(Ack),
        }
    }

    fn secure_channel_key(&mut self, selection: PdSecureKey) -> Option<[u8; 16]> {
        match selection {
            PdSecureKey::ScbkD => Some(SCBK_D),
            PdSecureKey::Scbk => None,
        }
    }
}

impl AcuSecureKeyProvider for DemoAcuKeys {
    fn secure_key_for(&mut self, _pd_addr: u8) -> Option<AcuSecureKeyMaterial> {
        Some(AcuSecureKeyMaterial {
            selection: AcuSecureKey::ScbkD,
            scbk: SCBK_D,
        })
    }
}

struct LoopbackTransport {
    pd: Pd<VecTransport, SystemClock, DemoPd>,
    rng: FixedRandom,
    incoming: VecDeque<u8>,
}

impl LoopbackTransport {
    fn new() -> Self {
        Self {
            pd: Pd::new(VecTransport::new(), SystemClock::new(), 0x05, DemoPd)
                .with_secure_channel(PdSecureConfig { cuid: [0xC1; 8] }),
            rng: FixedRandom([0xB2; 8]),
            incoming: VecDeque::new(),
        }
    }
}

impl Transport for LoopbackTransport {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.pd.transport().feed(bytes);
        self.pd.poll_once_with_rng(&mut self.rng)?;
        self.incoming.extend(self.pd.transport().outgoing.drain(..));
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

fn main() -> Result<(), Error> {
    let mut acu = Acu::new(LoopbackTransport::new(), SystemClock::new());
    let mut state = PdState::default();
    let mut keys = DemoAcuKeys;
    let mut rng = FixedRandom([0xA1; 8]);

    acu.establish_secure_channel(0x05, &mut state, &mut keys, &mut rng)?;
    println!(
        "secure channel established; next SQN {}",
        state.next_sqn.value()
    );

    let poll = acu.exchange(0x05, &mut state, &Command::Poll(Poll))?;
    println!("secure POLL -> {poll:?}");

    let id = acu.exchange(0x05, &mut state, &Command::Id(Id::standard()))?;
    println!("secure ID -> {id:?}");

    Ok(())
}
