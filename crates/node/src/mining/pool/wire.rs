//! Bounded Monario pool framing. This is a project-specific extension, not
//! Bitcoin Stratum V2 and not claimed interoperable with it.
//!
//! Every frame is `magic(4) || version(1) || kind(1) || payload_len(4 LE)` plus
//! an exact payload. Control frames are capped at 4 KiB; a job frame is capped at
//! one canonical work packet. The decoder never allocates from an unvalidated
//! peer length and rejects trailing bytes, truncation and unknown kinds.
use std::io::{self, Write};
use zeroize::Zeroize;

pub const MAGIC: [u8; 4] = *b"MONP";
pub const VERSION: u8 = 1;
pub const HEADER: usize = 10;
pub const MAX_CONTROL_PAYLOAD: usize = 4_096;
/// `Work::encode` is at most the 5,000,000-byte block limit plus its 72-byte prefix.
pub const MAX_JOB_PACKET: usize = 5_000_072;
const JOB_FIXED: usize = 32 + 32 + 32 + 24 + 8 + 8 + 32 + 4;
pub const MAX_JOB_PAYLOAD: usize = JOB_FIXED + MAX_JOB_PACKET;
pub const MAX_BUFFER: usize = HEADER + MAX_JOB_PAYLOAD;
const MAX_MESSAGES_PER_FEED: usize = 32;
const MAX_WRITES_PER_POLL: usize = 4;

pub const AUTH: u8 = 1;
pub const AUTH_OK: u8 = 2;
pub const ERROR: u8 = 3;
pub const JOB: u8 = 4;
pub const SUBMIT: u8 = 5;
pub const ACCEPTED: u8 = 6;
pub const REJECTED: u8 = 7;

pub const MALFORMED: u8 = 1;
pub const UNAUTHENTICATED: u8 = 2;
pub const UNAUTHORIZED: u8 = 3;
pub const STALE: u8 = 4;
pub const DUPLICATE: u8 = 5;
pub const INVALID: u8 = 6;
pub const QUOTA: u8 = 7;
pub const BUSY: u8 = 8;
pub const SHUTDOWN: u8 = 9;

#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    Auth {
        client: [u8; 16],
        token: [u8; 32],
    },
    AuthOk {
        session: [u8; 16],
    },
    Error {
        code: u8,
    },
    Job {
        assignment: [u8; 32],
        parent: [u8; 32],
        job: [u8; 32],
        prefix: [u8; 24],
        start: u64,
        end: u64,
        target: [u8; 32],
        packet: Vec<u8>,
    },
    Submit {
        assignment: [u8; 32],
        job: [u8; 32],
        nonce: [u8; 32],
    },
    Accepted {
        units: u64,
        block_candidate: bool,
    },
    Rejected {
        code: u8,
    },
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth { client, .. } => f
                .debug_struct("Auth")
                .field("client", client)
                .field("token", &"[redacted]")
                .finish(),
            Self::AuthOk { session } => f.debug_struct("AuthOk").field("session", session).finish(),
            Self::Error { code } => f.debug_struct("Error").field("code", code).finish(),
            Self::Job {
                assignment,
                parent,
                job,
                prefix,
                start,
                end,
                target,
                packet,
            } => f
                .debug_struct("Job")
                .field("assignment", assignment)
                .field("parent", parent)
                .field("job", job)
                .field("prefix", prefix)
                .field("start", start)
                .field("end", end)
                .field("target", target)
                .field("packet_len", &packet.len())
                .finish(),
            Self::Submit {
                assignment,
                job,
                nonce,
            } => f
                .debug_struct("Submit")
                .field("assignment", assignment)
                .field("job", job)
                .field("nonce", nonce)
                .finish(),
            Self::Accepted {
                units,
                block_candidate,
            } => f
                .debug_struct("Accepted")
                .field("units", units)
                .field("block_candidate", block_candidate)
                .finish(),
            Self::Rejected { code } => f.debug_struct("Rejected").field("code", code).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Oversized,
    Io,
}

pub fn encode(message: &Message) -> Result<Vec<u8>, Error> {
    let mut payload = Vec::new();
    let kind = match message {
        Message::Auth { client, token } => {
            payload.extend_from_slice(client);
            payload.extend_from_slice(token);
            AUTH
        }
        Message::AuthOk { session } => {
            payload.extend_from_slice(session);
            AUTH_OK
        }
        Message::Error { code } => {
            payload.push(*code);
            ERROR
        }
        Message::Job {
            assignment,
            parent,
            job,
            prefix,
            start,
            end,
            target,
            packet,
        } => {
            if packet.len() > MAX_JOB_PACKET {
                return Err(Error::Oversized);
            }
            payload.extend_from_slice(assignment);
            payload.extend_from_slice(parent);
            payload.extend_from_slice(job);
            payload.extend_from_slice(prefix);
            payload.extend_from_slice(&start.to_le_bytes());
            payload.extend_from_slice(&end.to_le_bytes());
            payload.extend_from_slice(target);
            payload.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            payload.extend_from_slice(packet);
            JOB
        }
        Message::Submit {
            assignment,
            job,
            nonce,
        } => {
            payload.extend_from_slice(assignment);
            payload.extend_from_slice(job);
            payload.extend_from_slice(nonce);
            SUBMIT
        }
        Message::Accepted {
            units,
            block_candidate,
        } => {
            payload.extend_from_slice(&units.to_le_bytes());
            payload.push(u8::from(*block_candidate));
            ACCEPTED
        }
        Message::Rejected { code } => {
            payload.push(*code);
            REJECTED
        }
    };
    if payload.len() > limit(kind)? {
        return Err(Error::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| Error::Oversized)?;
    let mut frame = Vec::with_capacity(HEADER + payload.len());
    frame.extend_from_slice(&MAGIC);
    frame.push(VERSION);
    frame.push(kind);
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode(frame: &[u8]) -> Result<Message, Error> {
    if frame.len() < HEADER || frame[..4] != MAGIC || frame[4] != VERSION {
        return Err(Error::Malformed);
    }
    let kind = frame[5];
    let length = usize::try_from(u32::from_le_bytes(
        frame[6..10].try_into().map_err(|_| Error::Malformed)?,
    ))
    .map_err(|_| Error::Malformed)?;
    if length > limit(kind)? {
        return Err(Error::Oversized);
    }
    if frame.len() != HEADER + length {
        return Err(Error::Malformed);
    }
    let mut cursor = Cursor::new(&frame[HEADER..]);
    let message = match kind {
        AUTH => Message::Auth {
            client: cursor.array()?,
            token: cursor.array()?,
        },
        AUTH_OK => Message::AuthOk {
            session: cursor.array()?,
        },
        ERROR => Message::Error {
            code: cursor.byte()?,
        },
        JOB => {
            let assignment = cursor.array()?;
            let parent = cursor.array()?;
            let job = cursor.array()?;
            let prefix = cursor.array()?;
            let start = cursor.u64()?;
            let end = cursor.u64()?;
            let target = cursor.array()?;
            let packet_len = usize::try_from(cursor.u32()?).map_err(|_| Error::Malformed)?;
            if packet_len > MAX_JOB_PACKET {
                return Err(Error::Oversized);
            }
            let packet = cursor.take(packet_len)?.to_vec();
            Message::Job {
                assignment,
                parent,
                job,
                prefix,
                start,
                end,
                target,
                packet,
            }
        }
        SUBMIT => Message::Submit {
            assignment: cursor.array()?,
            job: cursor.array()?,
            nonce: cursor.array()?,
        },
        ACCEPTED => {
            let units = cursor.u64()?;
            let block = cursor.byte()?;
            if block > 1 {
                return Err(Error::Malformed);
            }
            Message::Accepted {
                units,
                block_candidate: block == 1,
            }
        }
        REJECTED => Message::Rejected {
            code: cursor.byte()?,
        },
        _ => return Err(Error::Malformed),
    };
    if !cursor.done() {
        return Err(Error::Malformed);
    }
    Ok(message)
}

fn limit(kind: u8) -> Result<usize, Error> {
    match kind {
        AUTH | AUTH_OK | ERROR | SUBMIT | ACCEPTED | REJECTED => Ok(MAX_CONTROL_PAYLOAD),
        JOB => Ok(MAX_JOB_PAYLOAD),
        _ => Err(Error::Malformed),
    }
}

/// Incremental bounded frame reader. `feed` returns at most 32 messages so one
/// poll cannot consume unbounded CPU; leftover complete frames stay buffered for
/// the next call.
pub struct Reader {
    buffer: Vec<u8>,
    max: usize,
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

impl Reader {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            max: MAX_BUFFER,
        }
    }

    /// A server-side reader that never accepts a job frame from a client.
    pub fn new_control() -> Self {
        Self {
            buffer: Vec::new(),
            max: HEADER + MAX_CONTROL_PAYLOAD,
        }
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    pub fn clear(&mut self) {
        self.buffer.zeroize();
        self.buffer.clear();
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Message>, Error> {
        let result = self.feed_inner(bytes);
        if result.is_err() {
            self.clear();
        }
        result
    }

    fn feed_inner(&mut self, bytes: &[u8]) -> Result<Vec<Message>, Error> {
        if self
            .buffer
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > self.max)
        {
            return Err(Error::Oversized);
        }
        self.buffer.extend_from_slice(bytes);
        let mut messages = Vec::new();
        let mut at = 0;
        while self.buffer.len() - at >= HEADER {
            let kind = self.buffer[at + 5];
            let length = usize::try_from(u32::from_le_bytes(
                self.buffer[at + 6..at + HEADER]
                    .try_into()
                    .map_err(|_| Error::Malformed)?,
            ))
            .map_err(|_| Error::Malformed)?;
            if self.buffer[at..at + 4] != MAGIC || self.buffer[at + 4] != VERSION {
                return Err(Error::Malformed);
            }
            if length > limit(kind)? || length > self.max.saturating_sub(HEADER) {
                return Err(Error::Oversized);
            }
            let total = HEADER.checked_add(length).ok_or(Error::Oversized)?;
            if self.buffer.len() - at < total {
                break;
            }
            messages.push(decode(&self.buffer[at..at + total])?);
            at += total;
            if messages.len() >= MAX_MESSAGES_PER_FEED {
                break;
            }
        }
        if at > 0 {
            self.buffer.drain(..at);
        }
        Ok(messages)
    }
}

/// Bounded pending output. A single job frame may occupy the whole bound.
#[derive(Default)]
pub struct Writer {
    pending: Vec<u8>,
    at: usize,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn queued(&self) -> usize {
        self.pending.len().saturating_sub(self.at)
    }

    pub fn clear(&mut self) {
        self.pending.zeroize();
        self.pending.clear();
        self.at = 0;
    }

    pub fn queue(&mut self, message: &Message) -> Result<(), Error> {
        let frame = encode(message)?;
        if self
            .pending
            .len()
            .saturating_sub(self.at)
            .checked_add(frame.len())
            .is_none_or(|length| length > MAX_BUFFER)
        {
            return Err(Error::Oversized);
        }
        if self.at == self.pending.len() {
            self.pending.clear();
            self.at = 0;
        }
        self.pending.extend_from_slice(&frame);
        Ok(())
    }

    /// At most four writes per call. `WouldBlock` leaves the remainder queued.
    pub fn write_to(&mut self, output: &mut impl Write) -> Result<(), Error> {
        if self.at == self.pending.len() {
            self.pending.clear();
            self.at = 0;
            return Ok(());
        }
        for _ in 0..MAX_WRITES_PER_POLL {
            match output.write(&self.pending[self.at..]) {
                Ok(0) => return Err(Error::Io),
                Ok(n) => self.at += n,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(());
                }
                Err(_) => return Err(Error::Io),
            }
            if self.at == self.pending.len() {
                self.pending.clear();
                self.at = 0;
                return Ok(());
            }
        }
        Ok(())
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(length).ok_or(Error::Malformed)?;
        let bytes = self.bytes.get(self.at..end).ok_or(Error::Malformed)?;
        self.at = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Malformed)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(packet: Vec<u8>) -> Message {
        Message::Job {
            assignment: [1; 32],
            parent: [2; 32],
            job: [3; 32],
            prefix: [4; 24],
            start: 5,
            end: 6,
            target: [7; 32],
            packet,
        }
    }

    #[test]
    fn every_message_round_trips_and_rejects_trailing_or_wrong_bytes() {
        let messages = [
            Message::Auth {
                client: [1; 16],
                token: [2; 32],
            },
            Message::AuthOk { session: [3; 16] },
            Message::Error { code: SHUTDOWN },
            job(vec![9; 32]),
            Message::Submit {
                assignment: [4; 32],
                job: [5; 32],
                nonce: [6; 32],
            },
            Message::Accepted {
                units: 7,
                block_candidate: true,
            },
            Message::Rejected { code: STALE },
        ];
        for message in messages {
            let frame = encode(&message).unwrap();
            assert_eq!(decode(&frame).unwrap(), message);
            let mut trailing = frame;
            trailing.push(0);
            assert_eq!(decode(&trailing), Err(Error::Malformed));
            let mut bad = encode(&message).unwrap();
            bad[0] ^= 1;
            assert_eq!(decode(&bad), Err(Error::Malformed));
        }
    }

    #[test]
    fn auth_debug_redacts_the_token() {
        let message = Message::Auth {
            client: [1; 16],
            token: [0xab; 32],
        };
        let debug = format!("{message:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("171"));
    }

    #[test]
    fn malformed_lengths_kinds_and_flags_fail_before_allocation() {
        let mut frame = encode(&Message::Rejected { code: STALE }).unwrap();
        frame[5] = 99;
        assert_eq!(decode(&frame), Err(Error::Malformed));
        let mut huge = encode(&Message::Error { code: MALFORMED }).unwrap();
        huge[6..10].copy_from_slice(&(MAX_CONTROL_PAYLOAD as u32 + 1).to_le_bytes());
        assert_eq!(decode(&huge), Err(Error::Oversized));
        let mut accepted = encode(&Message::Accepted {
            units: 1,
            block_candidate: true,
        })
        .unwrap();
        *accepted.last_mut().unwrap() = 2;
        assert_eq!(decode(&accepted), Err(Error::Malformed));
        let oversized = job(vec![0; MAX_JOB_PACKET + 1]);
        assert_eq!(encode(&oversized), Err(Error::Oversized));
        assert_eq!(
            decode(&[MAGIC.as_slice(), &[VERSION]].concat()),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn reader_handles_fragmentation_multiple_frames_and_bounds_the_buffer() {
        let mut reader = Reader::new();
        let first = encode(&Message::AuthOk { session: [1; 16] }).unwrap();
        let second = encode(&Message::Rejected { code: DUPLICATE }).unwrap();
        let mut both = first.clone();
        both.extend_from_slice(&second);
        assert!(reader.feed(&both[..5]).unwrap().is_empty());
        let messages = reader.feed(&both[5..]).unwrap();
        assert_eq!(
            messages,
            vec![
                Message::AuthOk { session: [1; 16] },
                Message::Rejected { code: DUPLICATE }
            ]
        );
        assert_eq!(reader.buffered(), 0);
        let mut reader = Reader::new();
        assert_eq!(reader.feed(&vec![0; MAX_BUFFER + 1]), Err(Error::Oversized));
    }

    #[test]
    fn control_reader_rejects_a_job_header_before_buffering() {
        let mut reader = Reader::new_control();
        let frame = encode(&job(vec![0; MAX_JOB_PACKET])).unwrap();
        assert_eq!(reader.feed(&frame[..HEADER]), Err(Error::Oversized));
        assert_eq!(reader.buffered(), 0);
        let mut reader = Reader::new_control();
        let control = encode(&Message::Rejected { code: STALE }).unwrap();
        assert_eq!(
            reader.feed(&control).unwrap(),
            vec![Message::Rejected { code: STALE }]
        );
    }

    struct Partial {
        accepted: usize,
        bytes: Vec<u8>,
    }

    impl Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.accepted == 0 {
                self.accepted = 3;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = bytes.len().min(self.accepted);
            self.bytes.extend_from_slice(&bytes[..n]);
            self.accepted = if n == bytes.len() { 3 } else { 0 };
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_survives_partial_and_blocked_writes_with_a_hard_bound() {
        let mut writer = Writer::new();
        writer.queue(&Message::Rejected { code: STALE }).unwrap();
        let mut sink = Partial {
            accepted: 3,
            bytes: Vec::new(),
        };
        for _ in 0..100 {
            writer.write_to(&mut sink).unwrap();
            if writer.queued() == 0 {
                break;
            }
        }
        assert_eq!(writer.queued(), 0);
        assert_eq!(
            decode(&sink.bytes).unwrap(),
            Message::Rejected { code: STALE }
        );
        let mut writer = Writer::new();
        writer.queue(&job(vec![0; MAX_JOB_PACKET])).unwrap();
        assert_eq!(
            writer.queue(&Message::Rejected { code: STALE }),
            Err(Error::Oversized)
        );
    }
}
