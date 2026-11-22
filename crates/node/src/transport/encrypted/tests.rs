use super::*;
use crate::tests::{clock, node};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
    trace: Vec<u8>,
    eof: bool,
}
pub(crate) struct Memory {
    input: Rc<RefCell<Pipe>>,
    output: Rc<RefCell<Pipe>>,
    writes: usize,
    blocked: bool,
}
pub(crate) fn memory_pair() -> (Memory, Memory) {
    let a = Rc::new(RefCell::new(Pipe::default()));
    let b = Rc::new(RefCell::new(Pipe::default()));
    (
        Memory {
            input: a.clone(),
            output: b.clone(),
            writes: 0,
            blocked: false,
        },
        Memory {
            input: b,
            output: a,
            writes: 0,
            blocked: false,
        },
    )
}
impl Read for Memory {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut input = self.input.borrow_mut();
        if input.bytes.is_empty() {
            return if input.eof {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            };
        }
        let n = input.bytes.len().min(out.len()).min(97);
        for byte in &mut out[..n] {
            *byte = input.bytes.pop_front().unwrap();
        }
        Ok(n)
    }
}
impl Write for Memory {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.blocked {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.writes += 1;
        match self.writes % 4 {
            0 => return Err(io::ErrorKind::WouldBlock.into()),
            1 => return Err(io::ErrorKind::Interrupted.into()),
            _ => {}
        }
        let n = bytes.len().min(83);
        let mut output = self.output.borrow_mut();
        output.bytes.extend(&bytes[..n]);
        output.trace.extend(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn identity(n: u8) -> Identity {
    Identity::from_secret(Zeroizing::new([n; 32]))
}

#[test]
fn derived_transport_identities_are_stable_and_domain_separated() {
    let base = identity(7);
    let scan = base.derive(SCAN_DOMAIN).unwrap();
    let scan_again = base.derive(SCAN_DOMAIN).unwrap();
    let pool = base.derive(POOL_DOMAIN).unwrap();
    assert_eq!(scan.public_key(), scan_again.public_key());
    assert_ne!(scan.public_key(), base.public_key());
    assert_ne!(scan.public_key(), pool.public_key());
    assert!(base.derive(&[]).is_err());
    assert!(base.derive(&[0; 65]).is_err());
}
fn pair(profile: [u8; 32]) -> (SecureConnection<Memory>, SecureConnection<Memory>) {
    let (a, b) = memory_pair();
    let alice = identity(7);
    let bob = identity(11);
    (
        SecureConnection::new(
            a,
            &alice,
            Role::Initiator {
                remote_key: bob.public_key(),
            },
            profile,
            0,
        )
        .unwrap(),
        SecureConnection::new(b, &bob, Role::Responder, profile, 0).unwrap(),
    )
}
fn handshake(a: &mut SecureConnection<Memory>, b: &mut SecureConnection<Memory>) {
    for ms in 0..100 {
        a.inner.stream.advance(ms).unwrap();
        b.inner.stream.advance(ms).unwrap();
    }
    assert!(a.inner.stream.established && b.inner.stream.established);
}
fn frame(
    a: &mut SecureConnection<Memory>,
    b: &mut SecureConnection<Memory>,
    message: &[u8],
) -> Vec<u8> {
    assert_eq!(a.inner.stream.write(message).unwrap(), message.len());
    for _ in 0..1_000 {
        a.inner.stream.advance(100).unwrap();
    }
    b.inner
        .stream
        .stream
        .input
        .borrow_mut()
        .bytes
        .drain(..)
        .collect()
}
fn rejects(b: &mut SecureConnection<Memory>, bytes: &[u8]) {
    b.inner.stream.stream.input.borrow_mut().bytes.extend(bytes);
    let (_dir, mut node) = node();
    let id = node.add_peer(clock(100)).unwrap();
    let before = node.buffered_bytes();
    let mut failed = false;
    for _ in 0..100 {
        if b.poll(&mut node, id, clock(100)).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed);
    assert!(matches!(b.inner.stream.state, State::Closed));
    assert!(b.inner.stream.plain.iter().all(|x| *x == 0));
    assert_eq!(node.buffered_bytes().0, before.0);
    assert!(node.buffered_bytes().1 <= before.1);
    assert_eq!(b.poll(&mut node, id, clock(101)), Err(Error::Protocol));
    node.disconnect(id);
    assert_eq!(node.buffered_bytes(), (0, 0));
}

#[test]
fn fragmented_duplex_preserves_bytes_and_bounds_memory() {
    let (mut a, mut b) = pair([2; 32]);
    handshake(&mut a, &mut b);
    let data: Vec<u8> = (0..PLAIN * 3 + 19).map(|i| (i % 251) as u8).collect();
    let mut sent = [0; 2];
    let mut received = [Vec::new(), Vec::new()];
    for _ in 0..10_000 {
        for i in 0..2 {
            let (from, to) = if i == 0 {
                (&mut a, &mut b)
            } else {
                (&mut b, &mut a)
            };
            from.inner.stream.advance(100).unwrap();
            if sent[i] < data.len() {
                match from.inner.stream.write(&data[sent[i]..]) {
                    Ok(n) => sent[i] += n,
                    Err(e) => assert!(blocked(&e)),
                }
            }
            let mut out = [0; 47];
            match to.inner.stream.read(&mut out) {
                Ok(n) => received[i].extend_from_slice(&out[..n]),
                Err(e) => assert!(blocked(&e)),
            }
        }
        if received.iter().all(|r| r.len() == data.len()) {
            break;
        }
    }
    assert_eq!(received, [data.clone(), data.clone()]);
    for peer in [&a, &b] {
        assert_eq!(peer.inner.stream.input.len(), CIPHER);
        assert_eq!(peer.inner.stream.plain.len(), PLAIN);
        assert!(peer.inner.stream.output.len() <= CIPHER + 2);
        assert!(
            !peer
                .inner
                .stream
                .stream
                .output
                .borrow()
                .trace
                .windows(128)
                .any(|w| w == &data[..128])
        );
    }
}

#[test]
fn corruption_reordering_reflection_and_session_replay_fail_closed() {
    for attack in 0..5 {
        let (mut a, mut b) = pair([2; 32]);
        handshake(&mut a, &mut b);
        let first = frame(&mut a, &mut b, b"authenticated first message");
        let second = frame(&mut a, &mut b, b"authenticated second message");
        match attack {
            0 => {
                let mut bad = first;
                bad[4] ^= 1;
                rejects(&mut b, &bad);
            }
            1 => rejects(&mut b, &second),
            2 => rejects(&mut a, &first),
            3 => {
                let (mut c, mut d) = pair([2; 32]);
                handshake(&mut c, &mut d);
                rejects(&mut d, &first);
            }
            _ => {
                b.inner
                    .stream
                    .stream
                    .input
                    .borrow_mut()
                    .bytes
                    .extend(&first);
                let mut out = [0; 100];
                assert_eq!(b.inner.stream.read(&mut out).unwrap(), 27);
                rejects(&mut b, &first);
            }
        }
    }
}

#[test]
fn malformed_lengths_plaintext_and_truncation_are_rejected() {
    for len in [0u16, 16, (CIPHER + 1) as u16, u16::MAX] {
        let (mut a, mut b) = pair([2; 32]);
        handshake(&mut a, &mut b);
        rejects(&mut b, &len.to_le_bytes());
    }
    let (mut a, mut b) = pair([2; 32]);
    handshake(&mut a, &mut b);
    let bytes = frame(&mut a, &mut b, b"truncated authenticated record");
    b.inner.stream.stream.input.borrow_mut().eof = true;
    rejects(&mut b, &bytes[..bytes.len() - 1]);
    let (_dir, n) = node();
    let (_, mut responder) = pair(n.profile);
    rejects(&mut responder, &crate::tests::hello(&n, [9; 16]));
}

#[test]
fn low_order_ephemerals_and_wrong_handshake_lengths_are_rejected() {
    for key in [[0; 32], {
        let mut key = [0; 32];
        key[0] = 1;
        key
    }] {
        assert!(!valid_public(key));
        let (_, mut b) = pair([2; 32]);
        let mut message = 32u16.to_le_bytes().to_vec();
        message.extend(key);
        rejects(&mut b, &message);
    }
    for len in [0u16, 31, 33, u16::MAX] {
        let (_, mut b) = pair([2; 32]);
        rejects(&mut b, &len.to_le_bytes());
    }
}

#[test]
fn wrong_pins_profiles_and_handshake_tags_never_release_application_data() {
    for attack in 0..3 {
        let (mut a, mut b) = pair([2; 32]);
        if attack == 0 {
            a.inner.stream.role = Role::Initiator {
                remote_key: identity(99).public_key(),
            };
        }
        if attack == 1 {
            let (dummy, _) = memory_pair();
            let stream = std::mem::replace(&mut b.inner.stream.stream, dummy);
            b = SecureConnection::new(stream, &identity(11), Role::Responder, [3; 32], 0).unwrap();
        }
        let (_da, mut na) = node();
        let (_db, mut nb) = node();
        let ap = na.add_peer(clock(0)).unwrap();
        let bp = nb.add_peer(clock(0)).unwrap();
        let mut failed = false;
        for ms in 0..100 {
            if attack == 2 && a.inner.stream.step == 1 && b.inner.stream.step == 2 {
                let mut pipe = a.inner.stream.stream.input.borrow_mut();
                if let Some(byte) = pipe.bytes.back_mut() {
                    *byte ^= 1;
                }
            }
            if a.poll(&mut na, ap, clock(ms)).is_err() || b.poll(&mut nb, bp, clock(ms)).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(!na.peers[&ap].ready && !nb.peers[&bp].ready);
        // The initiator does not reveal its static key to a responder failing its pin.
        if attack == 0 {
            assert_eq!(a.inner.stream.stream.output.borrow().trace.len(), 34);
        }
    }
}

#[test]
fn absolute_deadlines_and_clock_regression_are_terminal() {
    for attack in 0..5 {
        let (mut a, mut b) = pair([2; 32]);
        if attack >= 2 {
            handshake(&mut a, &mut b);
        }
        let (_dir, mut n) = node();
        let p = n.add_peer(clock(100)).unwrap();
        let when = match attack {
            0 => HANDSHAKE_MS,
            1 => {
                b.poll(&mut n, p, clock(100)).unwrap();
                99
            }
            2 => {
                b.inner.stream.stream.input.borrow_mut().bytes.push_back(17);
                b.poll(&mut n, p, clock(100)).unwrap();
                100 + RECORD_MS
            }
            3 => SESSION_MS,
            _ => {
                b.inner
                    .stream
                    .write_all(b"stalled outgoing record")
                    .unwrap();
                // A permanently blocked socket must expire even if the Node send queue is empty.
                99 + RECORD_MS
            }
        };
        assert!(b.poll(&mut n, p, clock(when)).is_err());
        assert!(matches!(b.inner.stream.state, State::Closed));
    }
}

#[test]
fn direction_nonce_limits_close_before_key_reuse() {
    for outgoing in [false, true] {
        let (mut a, mut b) = pair([2; 32]);
        handshake(&mut a, &mut b);
        if outgoing {
            let State::Active(t) = &mut b.inner.stream.state else {
                panic!()
            };
            // Test-only access to Snow's nonce boundary; production never resets counters.
            for _ in 0..RECORD_LIMIT {
                t.write_message(&[], &mut [0; 16]).unwrap();
            }
            let (_dir, mut n) = node();
            let p = n.add_peer(clock(100)).unwrap();
            assert!(b.poll(&mut n, p, clock(100)).is_err());
            assert!(matches!(b.inner.stream.state, State::Closed));
        } else {
            let bytes = frame(&mut a, &mut b, b"nonce boundary");
            let State::Active(t) = &mut b.inner.stream.state else {
                panic!()
            };
            t.set_receiving_nonce(RECORD_LIMIT);
            rejects(&mut b, &bytes);
        }
    }
}

#[test]
fn direct_snow_peer_interoperates_without_wrapper_on_remote_side() {
    let alice = identity(7);
    let bob = identity(11);
    let (memory, remote) = memory_pair();
    let mut a = SecureConnection::new(
        memory,
        &alice,
        Role::Initiator {
            remote_key: bob.public_key(),
        },
        [2; 32],
        0,
    )
    .unwrap();
    let mut prologue = DOMAIN.to_vec();
    prologue.extend([2; 32]);
    let mut h = snow::Builder::new(PROTOCOL.parse().unwrap())
        .local_private_key(bob.0.as_ref())
        .unwrap()
        .prologue(&prologue)
        .unwrap()
        .build_responder()
        .unwrap();
    for _ in 0..20 {
        a.inner.stream.advance(0).unwrap();
    }
    let first: Vec<u8> = remote.input.borrow_mut().bytes.drain(..).collect();
    assert_eq!(&first[..2], &32u16.to_le_bytes());
    h.read_message(&first[2..], &mut []).unwrap();
    let mut second = [0; 96];
    assert_eq!(h.write_message(&[], &mut second).unwrap(), 96);
    remote.output.borrow_mut().bytes.extend(96u16.to_le_bytes());
    remote.output.borrow_mut().bytes.extend(second);
    for _ in 0..20 {
        a.inner.stream.advance(1).unwrap();
    }
    let third: Vec<u8> = remote.input.borrow_mut().bytes.drain(..).collect();
    assert_eq!(&third[..2], &64u16.to_le_bytes());
    h.read_message(&third[2..], &mut []).unwrap();
    assert_eq!(h.get_remote_static().unwrap(), alice.public_key());
    let mut t = h.into_transport_mode().unwrap();
    let text = b"independent Noise endpoint";
    a.inner.stream.write_all(text).unwrap();
    for _ in 0..20 {
        a.inner.stream.advance(2).unwrap();
    }
    let bytes: Vec<u8> = remote.input.borrow_mut().bytes.drain(..).collect();
    let mut out = [0; 100];
    let n = t.read_message(&bytes[2..], &mut out).unwrap();
    assert_eq!(&out[..n], text);
    let n = t.write_message(text, &mut out).unwrap();
    remote
        .output
        .borrow_mut()
        .bytes
        .extend((n as u16).to_le_bytes());
    remote.output.borrow_mut().bytes.extend(&out[..n]);
    let mut got = [0; 100];
    assert_eq!(a.inner.stream.read(&mut got).unwrap(), text.len());
    assert_eq!(&got[..text.len()], text);
}

#[test]
fn encrypted_node_handshake_sync_reorg_and_reopen() {
    let _serial = crate::tests::REAL.lock().unwrap();
    let (_da, mut na) = node();
    let (db, mut nb) = node();
    let root = na.source().chain().unwrap().tip();
    let first = crate::tests::append(&mut na, root, vec![], 0);
    let main = crate::tests::append(&mut na, first, vec![], 0);
    let (mut a, mut b) = pair(na.profile);
    let ap = na.add_outbound_peer(clock(0)).unwrap();
    let bp = nb.add_peer(clock(0)).unwrap();
    for ms in 0..1_000 {
        a.poll(&mut na, ap, clock(ms)).unwrap();
        b.poll(&mut nb, bp, clock(ms)).unwrap();
        na.tick(clock(ms)).unwrap();
        nb.tick(clock(ms)).unwrap();
    }
    assert!(na.peers[&ap].ready && nb.peers[&bp].ready);
    assert_eq!(nb.source().chain().unwrap().tip(), main);
    let chain = na.source().chain().unwrap();
    let template = chain
        .build_template(first, 1151, 1_000_000, vec![], |p| {
            Ok(crate::tests::coinbase(p, 0))
        })
        .unwrap();
    let bytes =
        monario_chain::wire::encode(&template.block, chain.limits(), &monario_v6::V6Verifier)
            .unwrap();
    let alt = na.import_block(&bytes, clock(1_000)).unwrap().id;
    assert_ne!(alt, main);
    let alt2 = crate::tests::append(&mut na, alt, vec![], 1_000);
    let alt3 = crate::tests::append(&mut na, alt2, vec![], 1_000);
    for ms in 1_000..2_000 {
        a.poll(&mut na, ap, clock(ms)).unwrap();
        b.poll(&mut nb, bp, clock(ms)).unwrap();
        na.tick(clock(ms)).unwrap();
        nb.tick(clock(ms)).unwrap();
    }
    assert_eq!(nb.source().chain().unwrap().tip(), alt3);
    nb.shutdown().unwrap();
    drop(nb);
    drop(b);
    let reopened = crate::tests::open(&db.path().join("node.sqlite"));
    assert_eq!(reopened.source().chain().unwrap().tip(), alt3);
    assert_eq!(reopened.peer_count(), 0);
}

#[test]
fn blocked_output_does_not_block_authenticated_input_and_still_expires() {
    let (_dir, mut n) = node();
    let (mut a, mut b) = pair(n.profile);
    handshake(&mut a, &mut b);
    a.inner
        .stream
        .write_all(b"already queued outgoing data")
        .unwrap();
    a.inner.stream.stream.blocked = true;
    let hello = crate::tests::hello(&n, [9; 16]);
    let bytes = frame(&mut b, &mut a, &hello);
    a.inner.stream.stream.input.borrow_mut().bytes.extend(bytes);
    let p = n.add_peer(clock(100)).unwrap();
    for _ in 0..5 {
        a.poll(&mut n, p, clock(100)).unwrap();
        n.tick(clock(100)).unwrap();
    }
    assert!(n.peers[&p].hello);
    assert_eq!(
        a.poll(&mut n, p, clock(99 + RECORD_MS)),
        Err(Error::Protocol)
    );
    assert!(matches!(a.inner.stream.state, State::Closed));
}

#[test]
fn invalid_static_peer_configuration_fails_without_opening_sockets() {
    use crate::transport::{PeerTarget, TcpConfig, TcpDriver};
    for attack in 0..4 {
        let local = identity(7);
        let key = match attack {
            0 => [0; 32],
            1 => {
                let mut key = [0; 32];
                key[0] = 1;
                key
            }
            2 => local.public_key(),
            _ => identity(11).public_key(),
        };
        let address = "127.0.0.1:12345".parse().unwrap();
        let mut targets = vec![PeerTarget {
            address,
            public_key: key,
        }];
        if attack == 3 {
            targets.push(PeerTarget {
                address,
                public_key: key,
            });
        }
        assert!(matches!(
            TcpDriver::new(TcpConfig {
                identity: local,
                listen: None,
                connect: targets
            }),
            Err(Error::Configuration)
        ));
    }
    let (stream, _) = memory_pair();
    assert!(matches!(
        SecureConnection::new(
            stream,
            &identity(7),
            Role::Initiator {
                remote_key: [0; 32]
            },
            [2; 32],
            0
        ),
        Err(Error::Configuration)
    ));
}
