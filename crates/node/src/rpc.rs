//! Bounded, authenticated, read-only management RPC.
//!
//! Construction binds a listener only through the explicit `Server::bind`
//! activation. It never mutates chain, wallet, mining or peer trust state. The
//! token is compared in constant time; requests and responses are bounded; every
//! error is generic. This is not a wallet API and never signs or exports secrets.
use crate::{Error, Node};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
};

pub const MAX_CONNECTIONS: usize = 8;
pub const MAX_REQUEST: usize = 16 * 1024;
pub const MAX_RESPONSE: usize = 64 * 1024;
pub const MAX_REQUESTS_PER_CONNECTION: usize = 256;
pub const IDLE_MS: u64 = 30_000;
pub const TOKEN_BYTES: usize = 32;
const READ_CHUNK: usize = 4096;

pub struct Config {
    pub bind: SocketAddr,
    pub token: [u8; TOKEN_BYTES],
    /// Explicit opt-in for a non-loopback bind. Loopback is the default policy.
    pub allow_remote: bool,
}

/// Parse a 64-character lowercase hexadecimal token, optionally terminated by a
/// single newline. An all-zero token is rejected; the operator must supply
/// independent randomness (for example, 32 bytes from a CSPRNG).
pub fn parse_token(bytes: &[u8]) -> Result<[u8; TOKEN_BYTES], Error> {
    let bytes = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    if bytes.len() != TOKEN_BYTES * 2
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(Error::Configuration);
    }
    let mut token = [0u8; TOKEN_BYTES];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        token[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    if token == [0; TOKEN_BYTES] {
        return Err(Error::Configuration);
    }
    Ok(token)
}

impl Config {
    fn validate(&self) -> Result<(), Error> {
        if self.bind.port() == 0
            || self.bind.ip().is_unspecified()
            || self.bind.ip().is_multicast()
            || self.token == [0; TOKEN_BYTES]
        {
            return Err(Error::Configuration);
        }
        if !self.allow_remote && !self.bind.ip().is_loopback() {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

pub struct Server {
    listener: TcpListener,
    token: [u8; TOKEN_BYTES],
    connections: Vec<Connection<TcpStream>>,
}

impl Server {
    /// EXPLICIT BIND. Never called by library construction or tests.
    pub fn bind(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind).map_err(|_| Error::Configuration)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            listener,
            token: config.token,
            connections: Vec::new(),
        })
    }

    /// One bounded, non-blocking poll. A bad connection is dropped; listener
    /// failure is fatal to the caller's runtime.
    pub fn poll(&mut self, node: &Node, now_ms: u64) -> Result<(), Error> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if self.connections.len() >= MAX_CONNECTIONS {
                        continue;
                    }
                    if stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    self.connections.push(Connection::new(stream, now_ms));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(Error::Io),
            }
        }
        let token = self.token;
        self.connections
            .retain_mut(|connection| connection.poll(node, &token, now_ms).is_ok());
        Ok(())
    }
}

struct Connection<S> {
    stream: S,
    token: [u8; TOKEN_BYTES],
    token_have: usize,
    authenticated: bool,
    read: Vec<u8>,
    write: Vec<u8>,
    write_at: usize,
    requests: usize,
    last: u64,
}

impl<S: Read + Write> Connection<S> {
    fn new(stream: S, now: u64) -> Self {
        Self {
            stream,
            token: [0; TOKEN_BYTES],
            token_have: 0,
            authenticated: false,
            read: Vec::new(),
            write: Vec::new(),
            write_at: 0,
            requests: 0,
            last: now,
        }
    }

    fn poll(&mut self, node: &Node, expected: &[u8; TOKEN_BYTES], now: u64) -> Result<(), ()> {
        if now.saturating_sub(self.last) > IDLE_MS || self.requests > MAX_REQUESTS_PER_CONNECTION {
            return Err(());
        }
        if self.write_at < self.write.len() {
            match self.stream.write(&self.write[self.write_at..]) {
                Ok(0) => return Err(()),
                Ok(written) => self.write_at += written,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(()),
            }
            if self.write_at == self.write.len() {
                self.write.clear();
                self.write_at = 0;
            }
        }
        if !self.authenticated {
            match self
                .stream
                .read(&mut self.token[self.token_have..TOKEN_BYTES])
            {
                Ok(0) => return Err(()),
                Ok(read) => {
                    self.token_have += read;
                    if self.token_have == TOKEN_BYTES {
                        if !constant_time_eq(&self.token, expected) {
                            return Err(());
                        }
                        self.authenticated = true;
                        self.write.push(0);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(()),
            }
        }
        if self.authenticated {
            let mut chunk = [0u8; READ_CHUNK];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(()),
                Ok(read) => {
                    self.read.extend_from_slice(&chunk[..read]);
                    self.last = now;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(()),
            }
            if self.read.len() > MAX_REQUEST + 1 {
                return Err(());
            }
            while let Some(position) = self.read.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.read.drain(..=position).collect();
                let line = &line[..line.len().saturating_sub(1)];
                if line.len() > MAX_REQUEST {
                    return Err(());
                }
                self.requests = self.requests.saturating_add(1);
                if self.requests > MAX_REQUESTS_PER_CONNECTION {
                    return Err(());
                }
                let response = handle_request(node, line);
                if self
                    .write
                    .len()
                    .saturating_sub(self.write_at)
                    .saturating_add(response.len() + 1)
                    > MAX_RESPONSE
                {
                    return Err(());
                }
                self.write.extend_from_slice(&response);
                self.write.push(b'\n');
            }
            if self.read.len() > MAX_REQUEST {
                return Err(());
            }
        }
        Ok(())
    }
}

fn constant_time_eq(a: &[u8; TOKEN_BYTES], b: &[u8; TOKEN_BYTES]) -> bool {
    let mut difference = 0u8;
    for index in 0..TOKEN_BYTES {
        difference |= a[index] ^ b[index];
    }
    difference == 0
}

fn response(id: Value, result: Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(&json!({"id": id, "ok": true, "result": result}))
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"internal\"}".to_vec());
    if bytes.len() > MAX_RESPONSE {
        return error(id, "response-too-large");
    }
    bytes
}

fn error(id: Value, code: &'static str) -> Vec<u8> {
    serde_json::to_vec(&json!({"id": id, "ok": false, "error": code}))
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"internal\"}".to_vec())
}

fn hash(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn params_id(params: Option<&Value>) -> Result<[u8; 32], &'static str> {
    let params = params.ok_or("invalid-params")?;
    let text = params
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or("invalid-params")?;
    hash(text).ok_or("invalid-params")
}

fn handle_request(node: &Node, line: &[u8]) -> Vec<u8> {
    if line.len() > MAX_REQUEST {
        return error(Value::Null, "request-too-large");
    }
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return error(Value::Null, "invalid-json");
    };
    let Some(object) = value.as_object() else {
        return error(Value::Null, "invalid-request");
    };
    let id = object.get("id").cloned().unwrap_or(Value::Null);
    if !(id.is_null() || id.is_string() || id.is_number()) {
        return error(Value::Null, "invalid-id");
    }
    let Some(method) = object.get("method").and_then(|value| value.as_str()) else {
        return error(id, "invalid-method");
    };
    let params = object.get("params");
    let result = match method {
        "status" => status(node),
        "block" => block(node, params),
        "block-transactions" => block_transactions(node, params),
        "transaction" => transaction(node, params),
        "mempool" => Ok(json!({"count": node.mempool().len()})),
        "peers" => Ok(json!({"count": node.peer_count()})),
        "candidates" => Ok(json!({
            "untrusted": true,
            "candidates": node.candidates().iter().map(|candidate| json!({
                "address": candidate.address.to_string(),
                "public_key": hex(&candidate.public_key),
            })).collect::<Vec<_>>(),
        })),
        "ping" => Ok(json!({"pong": true})),
        _ => return error(id, "unknown-method"),
    };
    match result {
        Ok(value) => response(id, value),
        Err(code) => error(id, code),
    }
}

fn status(node: &Node) -> Result<Value, &'static str> {
    let chain = node.source().chain().map_err(|_| "unavailable")?;
    Ok(json!({
        "profile": hex(&chain.validation_profile()),
        "tip": hex(&chain.tip()),
        "height": chain.height().to_string(),
        "peers": node.peer_count(),
        "stopped": node.stopped(),
        "mempool_count": node.mempool().len(),
        "candidate_count": node.candidates().len(),
        "read_only": true,
    }))
}

fn block(node: &Node, params: Option<&Value>) -> Result<Value, &'static str> {
    let id = params_id(params)?;
    let info = node
        .source()
        .block_info(&id)
        .map_err(|_| "unavailable")?
        .ok_or("not-found")?;
    Ok(json!({
        "height": info.height.to_string(),
        "parent": info.parent.map(|parent| hex(&parent)),
        "commitment": hex(&info.commitment),
    }))
}

fn block_transactions(node: &Node, params: Option<&Value>) -> Result<Value, &'static str> {
    use monario_address::{Address, Network, Receiver};
    const MAX_IDS: usize = 24;
    const MAX_OUTPUTS: usize = 8;
    let id = params_id(params)?;
    let namespace = match params.and_then(|p| p.get("network")).and_then(Value::as_str) {
        Some("main") => Network::Main,
        Some("test") => Network::Test,
        Some("regtest") => Network::Regtest,
        _ => return Err("invalid-params"),
    };
    let source = node.source();
    let chain = source.chain().map_err(|_| "unavailable")?;
    let info = source.block_info(&id).map_err(|_| "unavailable")?.ok_or("not-found")?;
    if info.height == 0 {
        return Err("not-found");
    }
    let raw = source.authenticated_block_bytes(id).map_err(|_| "unavailable")?;
    let block = monario_chain::wire::decode(&raw, chain.limits(), &crate::V6Verifier)
        .map_err(|_| "unavailable")?;
    let ids = block.transactions.iter().take(MAX_IDS)
        .map(|bytes| monario_v6::transaction_id(bytes).map(|id| hex(&id)))
        .collect::<Result<Vec<_>, _>>().map_err(|_| "unavailable")?;
    let coinbase = block.transactions.first().ok_or("unavailable")?;
    let (output_count, outputs) = monario_v6::coinbase::transparent_outputs(coinbase, MAX_OUTPUTS)
        .map_err(|_| "unavailable")?;
    let outputs = outputs.into_iter().map(|(atoms, receiver)| {
        let address = receiver.map(|receiver| Address::new(namespace, Receiver::Transparent(receiver)).encode());
        json!({"atoms": atoms.to_string(), "address": address})
    }).collect::<Vec<_>>();
    Ok(json!({
        "transaction_count": block.transactions.len(),
        "ids": ids,
        "coinbase_output_count": output_count,
        "coinbase_outputs": outputs,
    }))
}

fn transaction(node: &Node, params: Option<&Value>) -> Result<Value, &'static str> {
    let id = params_id(params)?;
    let confirmation = node
        .source()
        .transaction_confirmation(&id)
        .map_err(|_| "unavailable")?
        .ok_or("not-found")?;
    Ok(json!({
        "block": hex(&confirmation.block),
        "height": confirmation.height.to_string(),
        "depth": confirmation.depth.to_string(),
        "confirmation_scope": "transaction-effects-id",
    }))
}

#[cfg(test)]
mod tests;
