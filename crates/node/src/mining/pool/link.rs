//! Nonblocking encrypted pool connection glue. `PoolLink` combines the hardened
//! Noise stream with the bounded pool reader/writer; it opens no socket and is
//! driven explicitly with caller-supplied monotonic time.
use super::wire;
use crate::transport::SecureStream;
use std::io::{self, Read, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Handshake,
    Wire(wire::Error),
    Io,
    Closed,
    NotEstablished,
}

pub struct PoolLink<S> {
    stream: SecureStream<S>,
    reader: wire::Reader,
    writer: wire::Writer,
    closed: bool,
}

impl<S: Read + Write> PoolLink<S> {
    pub fn new(stream: SecureStream<S>) -> Self {
        Self {
            stream,
            reader: wire::Reader::new(),
            writer: wire::Writer::new(),
            closed: false,
        }
    }

    /// Server-side link: only control frames are accepted from the peer.
    pub fn new_control(stream: SecureStream<S>) -> Self {
        Self {
            stream,
            reader: wire::Reader::new_control(),
            writer: wire::Writer::new(),
            closed: false,
        }
    }

    pub fn is_established(&self) -> bool {
        self.stream.established()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Advance the handshake, read at most one bounded chunk, parse at most 32
    /// messages, and flush queued output. No unbounded allocation is driven by a
    /// peer length.
    pub fn poll(&mut self, now: u64) -> Result<Vec<wire::Message>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        match self.stream.advance(now) {
            Ok(false) => return Ok(Vec::new()),
            Ok(true) => {}
            Err(_) => {
                self.closed = true;
                return Err(Error::Handshake);
            }
        }
        let mut input = [0u8; 4_096];
        let mut messages = Vec::new();
        match self.stream.read(&mut input) {
            Ok(0) => {
                self.closed = true;
                return Err(Error::Io);
            }
            Ok(n) => match self.reader.feed(&input[..n]) {
                Ok(parsed) => messages = parsed,
                Err(error) => {
                    self.close();
                    return Err(Error::Wire(error));
                }
            },
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => {
                self.closed = true;
                return Err(Error::Io);
            }
        }
        if let Err(error) = self.writer.write_to(&mut self.stream) {
            self.closed = true;
            return Err(Error::Wire(error));
        }
        // Flush the record produced by `write_to` before the next poll.
        if self.stream.advance(now).is_err() {
            self.closed = true;
            return Err(Error::Handshake);
        }
        Ok(messages)
    }

    /// Queue a bounded message. Call `poll` to encrypt and flush it.
    pub fn send(&mut self, message: &wire::Message) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if !self.stream.established() {
            return Err(Error::NotEstablished);
        }
        self.writer.queue(message).map_err(Error::Wire)
    }

    /// Flush queued messages without reading new input.
    pub fn flush(&mut self, now: u64) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if let Err(error) = self.writer.write_to(&mut self.stream) {
            self.closed = true;
            return Err(Error::Wire(error));
        }
        if self.stream.advance(now).is_err() {
            self.closed = true;
            return Err(Error::Handshake);
        }
        Ok(())
    }

    pub fn close(&mut self) {
        self.closed = true;
        self.reader.clear();
        self.writer.clear();
        self.stream.close();
    }
}

impl<S> Drop for PoolLink<S> {
    fn drop(&mut self) {
        // The reader/writer may briefly contain an encoded Auth token.
        self.reader.clear();
        self.writer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Identity, POOL_DOMAIN, Role};
    use zeroize::Zeroizing;

    #[test]
    fn encrypted_link_moves_frames_and_bounds_the_reader() {
        let (client_io, server_io) = crate::transport::isolated_memory_pair();
        let client_key = Identity::from_secret(Zeroizing::new([7; 32]));
        let server_key = Identity::from_secret(Zeroizing::new([11; 32]));
        let client_stream = SecureStream::new(
            client_io,
            &client_key,
            Role::Initiator {
                remote_key: server_key.public_key(),
            },
            [2; 32],
            POOL_DOMAIN,
            0,
        )
        .unwrap();
        let server_stream = SecureStream::new(
            server_io,
            &server_key,
            Role::Responder,
            [2; 32],
            POOL_DOMAIN,
            0,
        )
        .unwrap();
        let mut client = PoolLink::new(client_stream);
        let mut server = PoolLink::new(server_stream);
        let mut now = 0;
        for _ in 0..2_000 {
            now += 1;
            client.poll(now).unwrap();
            server.poll(now).unwrap();
            if client.is_established() && server.is_established() {
                break;
            }
        }
        assert!(client.is_established() && server.is_established());

        let message = wire::Message::Rejected { code: wire::STALE };
        client.send(&message).unwrap();
        let mut received = Vec::new();
        for _ in 0..2_000 {
            now += 1;
            client.poll(now).unwrap();
            received.extend(server.poll(now).unwrap());
            if !received.is_empty() {
                break;
            }
        }
        assert_eq!(received, vec![message]);

        // A second frame proves the reader drained exactly one frame and the
        // writer can queue again after the earlier output was flushed.
        let second = wire::Message::AuthOk { session: [4; 16] };
        server.send(&second).unwrap();
        let mut reply = Vec::new();
        for _ in 0..2_000 {
            now += 1;
            server.poll(now).unwrap();
            reply.extend(client.poll(now).unwrap());
            if !reply.is_empty() {
                break;
            }
        }
        assert_eq!(reply, vec![second]);
        client.close();
        assert!(client.is_closed());
        assert_eq!(client.poll(now), Err(Error::Closed));
    }
}
