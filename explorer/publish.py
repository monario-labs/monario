"""Publish a bounded, atomically replaced view of a validating peer's chain."""

import argparse
import json
import os
import re
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path


HASH = re.compile(r"[0-9a-f]{64}")
HEIGHT = re.compile(r"0|[1-9][0-9]{0,19}")
LIMIT = 24
MAX_REPLY = 65536
TESTNET_ADDRESS = re.compile(r"testmont1[023456789acdefghjklmnpqrstuvwxyz]{40,60}")


def hash_id(value):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValueError("invalid block identifier")
    return value


def height(value):
    if not isinstance(value, str) or not HEIGHT.fullmatch(value) or int(value) >= 2**64:
        raise ValueError("invalid block height")
    return int(value)


class PeerRPC:
    def __init__(self, connection, reader):
        self.connection = connection
        self.reader = reader
        self.sequence = 0

    def query(self, method, params=None):
        self.sequence += 1
        request = {"id": self.sequence, "method": method}
        if params is not None:
            request["params"] = params
        self.connection.sendall(json.dumps(request).encode("ascii") + b"\n")
        line = self.reader.readline(MAX_REPLY + 1)
        if not line.endswith(b"\n") or len(line) > MAX_REPLY:
            raise ValueError("invalid RPC response size")
        reply = json.loads(line)
        if (not isinstance(reply, dict) or type(reply.get("id")) is not int
                or reply["id"] != self.sequence or reply.get("ok") is not True
                or not isinstance(reply.get("result"), dict)):
            raise ValueError("RPC request failed")
        return reply["result"]


def read_tip(query, profile):
    status = query("status")
    if (status.get("profile") != profile or status.get("read_only") is not True
            or status.get("stopped") is not False):
        raise ValueError("node is stopped or on an unexpected profile")
    return hash_id(status.get("tip")), height(status.get("height"))


def transactions(query, block_id):
    result = query("block-transactions", {"id": block_id, "network": "test"})
    count = result.get("transaction_count")
    ids = result.get("ids")
    output_count = result.get("coinbase_output_count")
    outputs = result.get("coinbase_outputs")
    if (type(count) is not int or count < 1 or not isinstance(ids, list)
            or len(ids) != min(24, count) or type(output_count) is not int
            or output_count < 0 or not isinstance(outputs, list)
            or len(outputs) != min(8, output_count)):
        raise ValueError("invalid block transaction summary")
    rows = [hash_id(item) for item in ids]
    public_outputs = []
    for output in outputs:
        if not isinstance(output, dict):
            raise ValueError("invalid coinbase output")
        atoms = output.get("atoms")
        height(atoms)  # An atom count uses the same canonical unsigned integer encoding.
        address = output.get("address")
        if address is not None and (not isinstance(address, str) or not TESTNET_ADDRESS.fullmatch(address)):
            raise ValueError("invalid coinbase recipient")
        public_outputs.append({"atoms": atoms, "address": address})
    return {"transaction_count": count, "transaction_ids": rows,
            "coinbase_output_count": output_count, "coinbase_outputs": public_outputs}


def snapshot(query, profile):
    tip, tip_height = read_tip(query, profile)
    cursor = tip
    blocks = []
    for expected_height in range(tip_height, max(0, tip_height - LIMIT), -1):
        block = query("block", {"id": cursor})
        if height(block.get("height")) != expected_height:
            raise ValueError("block height does not follow the validated tip")
        parent = hash_id(block.get("parent"))
        blocks.append({"id": cursor, "height": str(expected_height), "parent": parent,
                       "commitment": hash_id(block.get("commitment")),
                       **transactions(query, cursor)})
        cursor = parent
    if read_tip(query, profile) != (tip, tip_height):
        raise ValueError("chain changed during snapshot")
    return {"version": 2, "network": "testnet", "profile": profile, "tip": tip, "height": str(tip_height),
            "generated_at": datetime.now(timezone.utc).isoformat(), "blocks": blocks}


def publish(path, document):
    stream = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".snapshot-", delete=False)
    pending = Path(stream.name)
    try:
        with stream:
            json.dump(document, stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        pending.chmod(0o644)
        pending.replace(path)
    finally:
        pending.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    hash_id(args.profile)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        with args.token_file.open("rb") as stream:
            encoded = stream.read(67).removesuffix(b"\n").removesuffix(b"\r")
        token = bytes.fromhex(hash_id(encoded.decode("ascii")))
        if token == bytes(32):
            raise ValueError("invalid RPC credential")
        with socket.create_connection(("127.0.0.1", args.port), timeout=3) as conn:
            conn.sendall(token)
            if conn.recv(1) != b"\0":
                raise ValueError("peer authentication failed")
            with conn.makefile("rb") as reader:
                document = snapshot(PeerRPC(conn, reader).query, args.profile)
        publish(args.output, document)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Explorer snapshot failed ({type(error).__name__}).\n")


if __name__ == "__main__":
    main()
