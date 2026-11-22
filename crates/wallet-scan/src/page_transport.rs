//! Bounded binary page transport.
//!
//! One connection carries a 32-byte token followed by one or more requests. Each
//! request is a 10-byte `(start_height, max_blocks)` pair. Each response is
//! `status u8 || length u32 LE || page bytes`. The token is compared in constant
//! time and every frame is bounded.
//!
//! There is no TLS. The node's scan server and the node-equipped client wrap this
//! framing in an authenticated Noise session; the plaintext `TcpPageSource` here is
//! retained only as a library primitive and test helper. This module creates no
//! listener; [`serve`] is a blocking helper for a caller that already owns a stream.
//! No wallet address is part of any request.

use super::{MAX_BLOCKS, MAX_PAGE_BYTES, Page, PageSource};
use crate::Error;
use monario_chain::storage::DurableChain;
use monario_v6::V6Verifier;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

pub const TOKEN_BYTES: usize = 32;
pub const REQUEST_BYTES: usize = 10;
pub const STATUS_BYTES: usize = 1;
pub const LENGTH_BYTES: usize = 4;
pub const MAX_REQUESTS_PER_STREAM: usize = 1_024;

/// One page request. `max_blocks` is bounded to the page format's limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub start_height: u64,
    pub max_blocks: u16,
}

impl Request {
    pub fn new(start_height: u64, max_blocks: usize) -> Result<Self, Error> {
        if start_height == 0 || max_blocks == 0 || max_blocks > MAX_BLOCKS {
            return Err(Error::Configuration);
        }
        Ok(Self {
            start_height,
            max_blocks: u16::try_from(max_blocks).map_err(|_| Error::Configuration)?,
        })
    }

    fn encode(self) -> [u8; REQUEST_BYTES] {
        let mut out = [0u8; REQUEST_BYTES];
        out[..8].copy_from_slice(&self.start_height.to_le_bytes());
        out[8..].copy_from_slice(&self.max_blocks.to_le_bytes());
        out
    }

    pub fn decode(bytes: [u8; REQUEST_BYTES]) -> Result<Self, Error> {
        let start_height = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| Error::Transport)?);
        let max_blocks = u16::from_le_bytes(bytes[8..].try_into().map_err(|_| Error::Transport)?);
        if start_height == 0 || max_blocks == 0 || usize::from(max_blocks) > MAX_BLOCKS {
            return Err(Error::Transport);
        }
        Ok(Self {
            start_height,
            max_blocks,
        })
    }
}

/// Response status. `Unavailable` is generic and never explains why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    AtTip,
    Unavailable,
}

impl Status {
    fn byte(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::AtTip => 1,
            Self::Unavailable => 2,
        }
    }

    fn decode(byte: u8) -> Result<Self, Error> {
        match byte {
            0 => Ok(Self::Ok),
            1 => Ok(Self::AtTip),
            2 => Ok(Self::Unavailable),
            _ => Err(Error::Transport),
        }
    }
}

/// One bounded response. `Ok` carries a nonempty page; the other statuses carry
/// no payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: Status,
    pub page: Vec<u8>,
}

impl Response {
    pub fn ok(page: Vec<u8>) -> Result<Self, Error> {
        if page.is_empty() || page.len() > MAX_PAGE_BYTES {
            return Err(Error::Capacity);
        }
        Ok(Self {
            status: Status::Ok,
            page,
        })
    }

    pub fn empty(status: Status) -> Self {
        Self {
            status,
            page: Vec::new(),
        }
    }

    fn check(&self) -> Result<(), Error> {
        match self.status {
            Status::Ok if self.page.is_empty() || self.page.len() > MAX_PAGE_BYTES => {
                Err(Error::Capacity)
            }
            Status::AtTip | Status::Unavailable if !self.page.is_empty() => Err(Error::Transport),
            _ => Ok(()),
        }
    }
}

/// Write a token and one request. The token must be nonzero.
pub fn write_request<S: Write>(
    stream: &mut S,
    token: &[u8; TOKEN_BYTES],
    request: Request,
) -> Result<(), Error> {
    if *token == [0; TOKEN_BYTES] {
        return Err(Error::Configuration);
    }
    stream
        .write_all(token)
        .and_then(|()| stream.write_all(&request.encode()))
        .and_then(|()| stream.flush())
        .map_err(|_| Error::Transport)
}

/// Read and authenticate one request. A bad token is indistinguishable from a
/// malformed frame to the caller; both return [`Error::Transport`].
pub fn read_request<S: Read>(
    stream: &mut S,
    expected: &[u8; TOKEN_BYTES],
) -> Result<Request, Error> {
    if *expected == [0; TOKEN_BYTES] {
        return Err(Error::Configuration);
    }
    let mut frame = [0u8; TOKEN_BYTES + REQUEST_BYTES];
    stream
        .read_exact(&mut frame)
        .map_err(|_| Error::Transport)?;
    if !constant_time_eq(&frame[..TOKEN_BYTES], expected) {
        return Err(Error::Transport);
    }
    let request = frame[TOKEN_BYTES..]
        .try_into()
        .map_err(|_| Error::Transport)?;
    Request::decode(request)
}

/// Write one bounded response.
pub fn write_response<S: Write>(
    stream: &mut S,
    response: &Response,
    max_page_bytes: usize,
) -> Result<(), Error> {
    response.check()?;
    if max_page_bytes == 0
        || max_page_bytes > MAX_PAGE_BYTES
        || response.page.len() > max_page_bytes
    {
        return Err(Error::Capacity);
    }
    let length = u32::try_from(response.page.len()).map_err(|_| Error::Capacity)?;
    stream
        .write_all(&[response.status.byte()])
        .and_then(|()| stream.write_all(&length.to_le_bytes()))
        .and_then(|()| stream.write_all(&response.page))
        .and_then(|()| stream.flush())
        .map_err(|_| Error::Transport)
}

/// Read one response, rejecting unknown statuses, impossible lengths and
/// status/payload mismatches before allocating the page.
pub fn read_response<S: Read>(stream: &mut S, max_page_bytes: usize) -> Result<Response, Error> {
    if max_page_bytes == 0 || max_page_bytes > MAX_PAGE_BYTES {
        return Err(Error::Configuration);
    }
    let mut head = [0u8; STATUS_BYTES + LENGTH_BYTES];
    stream.read_exact(&mut head).map_err(|_| Error::Transport)?;
    let status = Status::decode(head[0])?;
    let length = u32::from_le_bytes(head[1..].try_into().map_err(|_| Error::Transport)?);
    let length = usize::try_from(length).map_err(|_| Error::Transport)?;
    if length > max_page_bytes || length > MAX_PAGE_BYTES {
        return Err(Error::Capacity);
    }
    match status {
        Status::Ok if length == 0 => return Err(Error::Transport),
        Status::AtTip | Status::Unavailable if length != 0 => return Err(Error::Transport),
        _ => {}
    }
    let mut page = vec![0u8; length];
    stream.read_exact(&mut page).map_err(|_| Error::Transport)?;
    Ok(Response { status, page })
}

fn constant_time_eq(bytes: &[u8], expected: &[u8; TOKEN_BYTES]) -> bool {
    if bytes.len() != TOKEN_BYTES {
        return false;
    }
    let mut difference = 0u8;
    for (byte, expected) in bytes.iter().zip(expected.iter()) {
        difference |= byte ^ expected;
    }
    difference == 0
}

/// A stream-generic page client. It sends no wallet addresses and accepts only
/// bounded responses.
pub struct Client<S> {
    stream: S,
    token: [u8; TOKEN_BYTES],
    requests: usize,
}

impl<S: Read + Write> Client<S> {
    pub fn new(stream: S, token: [u8; TOKEN_BYTES]) -> Result<Self, Error> {
        if token == [0; TOKEN_BYTES] {
            return Err(Error::Configuration);
        }
        Ok(Self {
            stream,
            token,
            requests: 0,
        })
    }

    /// Request one page. `None` means the source reported its tip.
    pub fn request(
        &mut self,
        request: Request,
        max_page_bytes: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.requests >= MAX_REQUESTS_PER_STREAM {
            return Err(Error::Capacity);
        }
        write_request(&mut self.stream, &self.token, request)?;
        let response = read_response(&mut self.stream, max_page_bytes)?;
        self.requests = self.requests.saturating_add(1);
        match response.status {
            Status::Ok => Ok(Some(response.page)),
            Status::AtTip => Ok(None),
            Status::Unavailable => Err(Error::Transport),
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

/// A TCP page source. Construction connects explicitly; no listener is opened.
/// This is the plaintext loopback path; use `monario_node::scan_client::
/// SecurePageSource` for an encrypted, key-pinned endpoint.
pub struct TcpPageSource {
    client: Client<TcpStream>,
}

impl TcpPageSource {
    pub fn connect(
        address: SocketAddr,
        token: [u8; TOKEN_BYTES],
        timeout: Duration,
    ) -> Result<Self, Error> {
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || token == [0; TOKEN_BYTES]
            || timeout.is_zero()
        {
            return Err(Error::Configuration);
        }
        let stream = TcpStream::connect_timeout(&address, timeout).map_err(|_| Error::Transport)?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .and_then(|()| stream.set_nodelay(true))
            .map_err(|_| Error::Transport)?;
        Ok(Self {
            client: Client::new(stream, token)?,
        })
    }
}

impl PageSource for TcpPageSource {
    fn page(
        &mut self,
        start_height: u64,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        if max_bytes == 0 || max_bytes > MAX_PAGE_BYTES {
            return Err(Error::Configuration);
        }
        let request = Request::new(start_height, max_blocks)?;
        self.client.request(request, max_bytes)
    }
}

/// Assemble a response from a validated chain. This is a pure request handler so
/// a nonblocking server can call it after framing a request. Errors are generic.
pub fn handle_page_request(
    chain: &DurableChain<V6Verifier>,
    request: Request,
    max_page_bytes: usize,
) -> Response {
    if max_page_bytes == 0 || max_page_bytes > MAX_PAGE_BYTES {
        return Response::empty(Status::Unavailable);
    }
    let Ok(view) = chain.chain() else {
        return Response::empty(Status::Unavailable);
    };
    if request.start_height > view.height() {
        return Response::empty(Status::AtTip);
    }
    match Page::from_chain(
        chain,
        request.start_height,
        usize::from(request.max_blocks),
        max_page_bytes,
    )
    .and_then(|page| page.encode())
    {
        Ok(page) => Response::ok(page).unwrap_or_else(|_| Response::empty(Status::Unavailable)),
        Err(_) => Response::empty(Status::Unavailable),
    }
}

/// Blocking server helper for a caller that already owns a stream. It reads and
/// authenticates one token, then serves at most `max_requests` bounded requests.
/// The node runtime must use its own nonblocking state machine.
pub fn serve<S: Read + Write>(
    stream: &mut S,
    chain: &DurableChain<V6Verifier>,
    token: &[u8; TOKEN_BYTES],
    max_page_bytes: usize,
    max_requests: usize,
) -> Result<usize, Error> {
    if *token == [0; TOKEN_BYTES]
        || max_page_bytes == 0
        || max_page_bytes > MAX_PAGE_BYTES
        || max_requests == 0
        || max_requests > MAX_REQUESTS_PER_STREAM
    {
        return Err(Error::Configuration);
    }
    for served in 0..max_requests {
        let request = read_request(stream, token)?;
        let response = handle_page_request(chain, request, max_page_bytes);
        write_response(stream, &response, max_page_bytes)?;
        if served + 1 == max_requests {
            return Ok(max_requests);
        }
    }
    Ok(max_requests)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    struct Mock {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Mock {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl Read for Mock {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.input.read(out)
        }
    }

    impl Write for Mock {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn token() -> [u8; TOKEN_BYTES] {
        [7; TOKEN_BYTES]
    }

    fn request() -> Request {
        Request::new(5, 2).unwrap()
    }

    #[test]
    fn request_and_response_frames_round_trip() {
        let mut encoded = Vec::new();
        write_request(&mut encoded, &token(), request()).unwrap();
        let mut reader = Cursor::new(encoded);
        assert_eq!(read_request(&mut reader, &token()).unwrap(), request());

        let mut response_bytes = Vec::new();
        write_response(
            &mut response_bytes,
            &Response::ok(vec![1, 2, 3]).unwrap(),
            MAX_PAGE_BYTES,
        )
        .unwrap();
        let response = read_response(&mut Cursor::new(response_bytes), MAX_PAGE_BYTES).unwrap();
        assert_eq!(response.status, Status::Ok);
        assert_eq!(response.page, [1, 2, 3]);

        for status in [Status::AtTip, Status::Unavailable] {
            let mut bytes = Vec::new();
            write_response(&mut bytes, &Response::empty(status), MAX_PAGE_BYTES).unwrap();
            let response = read_response(&mut Cursor::new(bytes), MAX_PAGE_BYTES).unwrap();
            assert_eq!(response.status, status);
            assert!(response.page.is_empty());
        }
    }

    #[test]
    fn bad_tokens_and_malformed_requests_fail_closed() {
        let mut encoded = Vec::new();
        write_request(&mut encoded, &token(), request()).unwrap();
        assert!(read_request(&mut Cursor::new(encoded.clone()), &[8; TOKEN_BYTES]).is_err());
        assert!(read_request(&mut Cursor::new(encoded[..41].to_vec()), &token()).is_err());
        assert!(write_request(&mut Vec::new(), &[0; TOKEN_BYTES], request()).is_err());
        assert!(Request::new(0, 1).is_err());
        assert!(Request::new(1, 0).is_err());
        assert!(Request::new(1, MAX_BLOCKS + 1).is_err());
    }

    #[test]
    fn malformed_responses_are_rejected_before_allocation() {
        // Unknown status.
        let bytes = vec![9, 0, 0, 0, 0];
        assert!(read_response(&mut Cursor::new(bytes), MAX_PAGE_BYTES).is_err());

        // Ok with no payload.
        let mut bytes = vec![0, 0, 0, 0, 0];
        assert!(read_response(&mut Cursor::new(bytes), MAX_PAGE_BYTES).is_err());

        // AtTip with a payload.
        bytes = vec![1, 1, 0, 0, 0, 0];
        assert!(read_response(&mut Cursor::new(bytes), MAX_PAGE_BYTES).is_err());

        // Declared length above the caller bound.
        let mut bytes = vec![0];
        bytes.extend_from_slice(&u32::try_from(MAX_PAGE_BYTES + 1).unwrap().to_le_bytes());
        assert!(read_response(&mut Cursor::new(bytes), MAX_PAGE_BYTES).is_err());

        // Truncated payload.
        let bytes = vec![0, 3, 0, 0, 0, 1, 2];
        assert!(read_response(&mut Cursor::new(bytes), MAX_PAGE_BYTES).is_err());

        assert!(
            write_response(
                &mut Vec::new(),
                &Response::empty(Status::Ok),
                MAX_PAGE_BYTES
            )
            .is_err()
        );
        assert!(write_response(&mut Vec::new(), &Response::ok(vec![1]).unwrap(), 0).is_err());
    }

    #[test]
    fn client_bounds_and_tip_status_are_enforced() {
        let mut response = Vec::new();
        write_response(
            &mut response,
            &Response::ok(vec![4, 5]).unwrap(),
            MAX_PAGE_BYTES,
        )
        .unwrap();
        write_response(
            &mut response,
            &Response::empty(Status::AtTip),
            MAX_PAGE_BYTES,
        )
        .unwrap();
        let mut client = Client::new(Mock::new(response), token()).unwrap();
        assert_eq!(
            client.request(request(), MAX_PAGE_BYTES).unwrap(),
            Some(vec![4, 5])
        );
        assert_eq!(client.request(request(), MAX_PAGE_BYTES).unwrap(), None);

        let mut exhausted = Client::new(Mock::new(Vec::new()), token()).unwrap();
        exhausted.requests = MAX_REQUESTS_PER_STREAM;
        assert!(exhausted.request(request(), MAX_PAGE_BYTES).is_err());
    }

    #[test]
    fn zero_token_clients_and_sources_fail_closed() {
        assert!(Client::new(Mock::new(Vec::new()), [0; TOKEN_BYTES]).is_err());
        assert!(
            TcpPageSource::connect(
                "127.0.0.1:1".parse().unwrap(),
                [0; TOKEN_BYTES],
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            TcpPageSource::connect(
                "127.0.0.1:0".parse().unwrap(),
                token(),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            TcpPageSource::connect("127.0.0.1:1".parse().unwrap(), token(), Duration::ZERO)
                .is_err()
        );
    }
}
