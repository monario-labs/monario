use super::*;

fn token() -> [u8; TOKEN_BYTES] {
    [0x11; TOKEN_BYTES]
}

fn call(node: &Node, request: serde_json::Value) -> serde_json::Value {
    let line = serde_json::to_vec(&request).unwrap();
    let bytes = handle_request(node, &line);
    assert!(bytes.len() <= MAX_RESPONSE);
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn token_parsing_is_strict_and_rejects_zero() {
    let text = "11".repeat(32);
    assert_eq!(parse_token(text.as_bytes()).unwrap(), token());
    assert_eq!(
        parse_token((text.clone() + "\n").as_bytes()).unwrap(),
        token()
    );
    assert_eq!(
        parse_token((text.clone() + "\r\n").as_bytes()).unwrap(),
        token()
    );
    for bad in [
        String::new(),
        "11".into(),
        "11".repeat(31),
        "11".repeat(33),
        "AA".repeat(32),
        "00".repeat(32),
        text.clone() + "\n\n",
        text + " ",
    ] {
        assert!(parse_token(bad.as_bytes()).is_err(), "{bad:?}");
    }
}

#[test]
fn constant_time_comparison_is_exact() {
    assert!(constant_time_eq(&[7; 32], &[7; 32]));
    let mut other = [7; 32];
    other[31] ^= 1;
    assert!(!constant_time_eq(&[7; 32], &other));
    assert!(!constant_time_eq(&[0; 32], &[1; 32]));
}

#[test]
fn bind_policy_requires_loopback_or_explicit_remote_and_a_real_port() {
    let loopback: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let remote: SocketAddr = "192.0.2.1:9000".parse().unwrap();
    assert!(
        Config {
            bind: loopback,
            token: token(),
            allow_remote: false,
        }
        .validate()
        .is_ok()
    );
    assert!(
        Config {
            bind: remote,
            token: token(),
            allow_remote: false,
        }
        .validate()
        .is_err()
    );
    assert!(
        Config {
            bind: remote,
            token: token(),
            allow_remote: true,
        }
        .validate()
        .is_ok()
    );
    for bind in [
        "0.0.0.0:9000".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        "239.1.1.1:9000".parse().unwrap(),
    ] {
        assert!(
            Config {
                bind,
                token: token(),
                allow_remote: true,
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        Config {
            bind: loopback,
            token: [0; TOKEN_BYTES],
            allow_remote: false,
        }
        .validate()
        .is_err()
    );
}

#[test]
fn read_only_methods_return_bounded_public_data() {
    let (_dir, node) = crate::tests::node();
    let tip = node.source().chain().unwrap().tip();

    let status = call(&node, serde_json::json!({"id": 1, "method": "status"}));
    assert_eq!(status["id"], 1);
    assert_eq!(status["ok"], true);
    assert_eq!(status["result"]["tip"], hex(&tip));
    assert_eq!(status["result"]["read_only"], true);
    assert_eq!(status["result"]["mempool_count"], 0);

    let ping = call(&node, serde_json::json!({"id": "p", "method": "ping"}));
    assert_eq!(ping["result"]["pong"], true);
    assert_eq!(ping["id"], "p");

    let mempool = call(&node, serde_json::json!({"id": 2, "method": "mempool"}));
    assert_eq!(mempool["result"]["count"], 0);

    let peers = call(&node, serde_json::json!({"id": 3, "method": "peers"}));
    assert_eq!(peers["result"]["count"], 0);

    let candidates = call(&node, serde_json::json!({"id": 4, "method": "candidates"}));
    assert_eq!(candidates["result"]["untrusted"], true);
    assert_eq!(candidates["result"]["candidates"], serde_json::json!([]));
}

#[test]
fn unknown_malformed_and_oversized_requests_fail_generically() {
    let (_dir, node) = crate::tests::node();
    let unknown = call(
        &node,
        serde_json::json!({"id": 5, "method": "not-a-method"}),
    );
    assert_eq!(unknown["ok"], false);
    assert_eq!(unknown["error"], "unknown-method");
    assert_eq!(unknown["id"], 5);

    let invalid = handle_request(&node, b"{not json");
    let value: serde_json::Value = serde_json::from_slice(&invalid).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"], "invalid-json");

    let no_method = call(&node, serde_json::json!({"id": 6}));
    assert_eq!(no_method["error"], "invalid-method");

    let bad_id = handle_request(&node, br#"{"id":{},"method":"status"}"#);
    let value: serde_json::Value = serde_json::from_slice(&bad_id).unwrap();
    assert_eq!(value["error"], "invalid-id");

    let missing = call(
        &node,
        serde_json::json!({"id": 7, "method": "transaction", "params": {}}),
    );
    assert_eq!(missing["error"], "invalid-params");

    let not_found = call(
        &node,
        serde_json::json!({
            "id": 8,
            "method": "block",
            "params": {"id": "00".repeat(32)}
        }),
    );
    assert_eq!(not_found["error"], "not-found");

    let oversized = vec![b'x'; MAX_REQUEST + 1];
    let value: serde_json::Value =
        serde_json::from_slice(&handle_request(&node, &oversized)).unwrap();
    assert_eq!(value["error"], "request-too-large");
}

struct Mock {
    input: Vec<u8>,
    at: usize,
    output: Vec<u8>,
}

impl Read for Mock {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.at >= self.input.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        let count = (self.input.len() - self.at).min(buffer.len());
        buffer[..count].copy_from_slice(&self.input[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

impl Write for Mock {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn connection_handshake_framing_and_quotas_are_bounded() {
    let (_dir, node) = crate::tests::node();
    let token = token();

    let mut input = token.to_vec();
    input.extend_from_slice(b"{\"id\":1,\"method\":\"ping\"}\n");
    let mut connection = Connection::new(
        Mock {
            input,
            at: 0,
            output: Vec::new(),
        },
        0,
    );
    connection.poll(&node, &token, 0).unwrap();
    connection.poll(&node, &token, 0).unwrap();
    let output = &connection.stream.output;
    assert_eq!(output[0], 0);
    let line = std::str::from_utf8(&output[1..]).unwrap().trim();
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(value["id"], 1);
    assert_eq!(value["result"]["pong"], true);

    let mut wrong = Connection::new(
        Mock {
            input: vec![0; TOKEN_BYTES],
            at: 0,
            output: Vec::new(),
        },
        0,
    );
    assert!(wrong.poll(&node, &token, 0).is_err());

    let mut partial = Connection::new(
        Mock {
            input: token[..16].to_vec(),
            at: 0,
            output: Vec::new(),
        },
        0,
    );
    assert!(partial.poll(&node, &token, 0).is_ok());
    assert!(partial.poll(&node, &token, IDLE_MS + 1).is_err());

    let mut oversized_input = token.to_vec();
    oversized_input.extend_from_slice(&vec![b'x'; MAX_REQUEST + 2]);
    let mut oversized = Connection::new(
        Mock {
            input: oversized_input,
            at: 0,
            output: Vec::new(),
        },
        0,
    );
    let mut rejected = false;
    for _ in 0..16 {
        if oversized.poll(&node, &token, 0).is_err() {
            rejected = true;
            break;
        }
    }
    assert!(rejected);

    let mut many_input = token.to_vec();
    for _ in 0..MAX_REQUESTS_PER_CONNECTION + 1 {
        many_input.extend_from_slice(b"{\"id\":1,\"method\":\"ping\"}\n");
    }
    let mut many = Connection::new(
        Mock {
            input: many_input,
            at: 0,
            output: Vec::new(),
        },
        0,
    );
    let mut rejected = false;
    for _ in 0..16 {
        if many.poll(&node, &token, 0).is_err() {
            rejected = true;
            break;
        }
    }
    assert!(rejected);
}
