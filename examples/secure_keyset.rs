//! Secure KEYSET example: install a new SCBK while using SCBK-D, then
//! reconnect with the installed SCBK.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example secure_keyset --features secure-channel
//! ```

use osdp::Error;
use osdp::clock::SystemClock;
use osdp::command::{Command, KeySet};
use osdp::driver::acu::{
    Acu, AcuSecureKey, AcuSecureKeyMaterial, AcuSecureKeyProvider, ExchangeOutcome, PdState,
};
use osdp::driver::pd::{Pd, PdHandler, PdSecureConfig, PdSecureKey, PdSecureKeyProvider};
use osdp::packet::ParsedPacket;
use osdp::reply::{Ack, Nak, NakErrorCode, Reply};
use osdp::secure::{SCBK_D, SecureRandom};
use osdp::transport::{Transport, VecTransport};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

const PD_ADDR: u8 = 0x05;
const INSTALLED_SCBK: [u8; 16] = [0x5A; 16];

#[derive(Debug, Default)]
struct KeyStore {
    install_mode: bool,
    scbk: Option<[u8; 16]>,
}

struct DemoPd {
    store: Rc<RefCell<KeyStore>>,
}

struct DemoPdKeys {
    store: Rc<RefCell<KeyStore>>,
}

struct DemoAcuKeys {
    scbk: Option<[u8; 16]>,
}

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
            Command::KeySet(keyset) if keyset.key_type == 0x01 && keyset.key.len() == 16 => {
                let mut scbk = [0u8; 16];
                scbk.copy_from_slice(&keyset.key);
                let mut store = self.store.borrow_mut();
                store.scbk = Some(scbk);
                store.install_mode = false;
                Reply::Ack(Ack)
            }
            Command::KeySet(_) => {
                Reply::Nak(Nak::simple(NakErrorCode::UnableToProcessCommandRecord))
            }
            _ if self.store.borrow().install_mode => {
                Reply::Nak(Nak::simple(NakErrorCode::UnableToProcessCommandRecord))
            }
            _ => Reply::Ack(Ack),
        }
    }
}

impl PdSecureKeyProvider for DemoPdKeys {
    fn secure_key_for(&mut self, selection: PdSecureKey) -> Option<[u8; 16]> {
        let store = self.store.borrow();
        match selection {
            PdSecureKey::Scbk => store.scbk,
            PdSecureKey::ScbkD if store.install_mode => Some(SCBK_D),
            PdSecureKey::ScbkD => None,
        }
    }
}

impl AcuSecureKeyProvider for DemoAcuKeys {
    fn secure_key_for(&mut self, _pd_addr: u8) -> Option<AcuSecureKeyMaterial> {
        match self.scbk {
            Some(scbk) => Some(AcuSecureKeyMaterial {
                selection: AcuSecureKey::Scbk,
                scbk,
            }),
            None => Some(AcuSecureKeyMaterial {
                selection: AcuSecureKey::ScbkD,
                scbk: SCBK_D,
            }),
        }
    }
}

struct LoopbackTransport {
    pd: Pd<VecTransport, SystemClock, DemoPd, DemoPdKeys>,
    rng: FixedRandom,
    incoming: VecDeque<u8>,
    writes: Vec<Vec<u8>>,
}

impl LoopbackTransport {
    fn new() -> Self {
        let store = Rc::new(RefCell::new(KeyStore {
            install_mode: true,
            scbk: None,
        }));
        Self {
            pd: Pd::new(
                VecTransport::new(),
                SystemClock::new(),
                PD_ADDR,
                DemoPd {
                    store: store.clone(),
                },
            )
            .with_secure_channel(
                PdSecureConfig { cuid: [0xC1; 8] },
                DemoPdKeys {
                    store: store.clone(),
                },
            ),
            rng: FixedRandom([0xB2; 8]),
            incoming: VecDeque::new(),
            writes: Vec::new(),
        }
    }
}

impl Transport for LoopbackTransport {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.writes.push(bytes.to_vec());
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
    let mut pd_state = PdState::default();
    let mut acu_keys = DemoAcuKeys { scbk: None };
    let mut rng = FixedRandom([0xA1; 8]);

    acu.establish_secure_channel(PD_ADDR, &mut pd_state, &mut acu_keys, &mut rng)?;
    println!("install-mode secure channel established with SCBK-D");

    match acu.exchange(
        PD_ADDR,
        &mut pd_state,
        &Command::KeySet(KeySet::scbk(INSTALLED_SCBK)),
    )? {
        ExchangeOutcome::Reply(Reply::Ack(_)) => {
            acu_keys.scbk = Some(INSTALLED_SCBK);
            println!("KEYSET ACK received; ACU stored installed SCBK");
        }
        other => {
            println!("KEYSET failed: {other:?}");
            return Ok(());
        }
    }

    pd_state.reset();
    rng = FixedRandom([0xA3; 8]);
    let reconnect_start = acu.transport().writes.len();
    acu.establish_secure_channel(PD_ADDR, &mut pd_state, &mut acu_keys, &mut rng)?;

    let first_reconnect_write = &acu.transport().writes[reconnect_start];
    let (parsed, _) = ParsedPacket::parse(first_reconnect_write)?;
    println!(
        "reconnected with current SCBK; SCS_11 selector {:?}",
        parsed.scb.unwrap().data
    );

    Ok(())
}
