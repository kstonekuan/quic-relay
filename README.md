# quic-relay

Lightweight UDP relay server for NAT traversal fallback. When direct STUN + UDP hole punching fails (e.g. symmetric NATs, corporate firewalls), both peers register with this relay and all QUIC traffic is forwarded through it transparently.

## Protocol

1. Each peer sends `REG:<session_uuid>\n` to the relay
2. Relay responds `ACK\n`
3. Once two peers register for the same session, all subsequent UDP datagrams are forwarded bidirectionally
4. Sessions are cleaned up after 5 minutes of inactivity (configurable)

The relay is protocol-agnostic after registration -- it forwards raw UDP datagrams without inspection, so QUIC runs through it unmodified.

## Build

```bash
cargo build --release
```

The release binary is ~2MB stripped.

## Usage

```bash
# Default: listen on UDP port 4433, 5-minute session timeout
./quic-relay

# Custom port and timeout
./quic-relay --port 5000 --session-timeout-secs 600
```

Set `RUST_LOG` for log verbosity:

```bash
RUST_LOG=debug ./quic-relay
```

## Deploy on AWS

### EC2

1. Launch a `t3.micro` instance in a region close to your Modal containers (e.g. `ap-southeast-1` for Modal's `ap` region)
2. Assign an Elastic IP for a stable address
3. Security group: allow inbound UDP on port 4433
4. Copy the release binary and run it (or use the Docker image)

### Docker

```bash
docker build -t quic-relay .
docker run -p 4433:4433/udp quic-relay
```

## Integration with openpi

Set the relay address in `hosting/src/hosting/modal_helpers.py`:

```python
RELAY_ADDR = ("your-elastic-ip", 4433)
```

The hosting layer will automatically fall back to the relay when direct hole punching fails. When `RELAY_ADDR` is `None` (default), relay fallback is disabled and the existing hole-punch-only behavior is preserved.

## License

MIT License
