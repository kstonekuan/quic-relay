# quic-relay

> **Status: Work in progress.** The relay server works and forwards traffic, but end-to-end QUIC-over-relay is not yet verified. See [Known Issues](#known-issues).

Lightweight UDP relay server for NAT traversal fallback. When direct STUN + UDP hole punching fails (e.g. symmetric NATs, corporate firewalls), both peers register with this relay and all QUIC traffic is forwarded through it transparently.

## Protocol

1. Each peer sends `REG:<session_uuid>\n` to the relay
2. Relay responds `ACK\n`
3. Once two peers register for the same session, all subsequent UDP datagrams are forwarded bidirectionally
4. Sessions are cleaned up after 5 minutes of inactivity (configurable)

The relay handles NAT port rebinding -- if a peer's external port changes (e.g. socket close + rebind), the relay detects the same IP and updates the session automatically.

## Build

```bash
cargo build --release
```

The release binary is ~2MB stripped. A GitHub Actions workflow builds the Linux x86_64 binary on every push to `main`.

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

## Deploy on AWS EC2

1. Launch a `t3.micro` instance (e.g. `ap-southeast-1` for Modal's `ap` region)
2. Assign an Elastic IP for a stable address
3. Security group: allow inbound UDP on port 4433
4. Download the binary from GitHub Actions artifacts:

```bash
# From your local machine
gh run download --name quic-relay-linux-x86_64 --dir /tmp/quic-relay-artifact
scp -i ~/.ssh/your-key.pem /tmp/quic-relay-artifact/quic-relay ubuntu@your-ec2:~/
```

5. Start it on EC2:

```bash
ssh -i ~/.ssh/your-key.pem ubuntu@your-ec2
chmod +x ~/quic-relay
nohup ~/quic-relay --port 4433 > ~/quic-relay.log 2>&1 &
```

## Integration with openpi

### Prerequisites

The relay requires a patched version of [quic-portal](https://github.com/Hebbian-Robotics/quic-portal) that adds `SO_REUSEPORT` to Quinn's sockets, allowing the keepalive socket and Quinn to coexist on the same port.

### Configuration

Set `QUIC_RELAY_IP` in `hosting/.env`:

```
QUIC_RELAY_IP=your-elastic-ip
```

To skip hole punching and always use the relay:

```
QUIC_RELAY_IP=your-elastic-ip
QUIC_RELAY_ONLY=true
```

The hosting layer reads these via `modal.Secret.from_dotenv()` and injects them into the Modal container. The client discovers the relay address from the Modal Dict automatically.

### How it works

1. Server registers with relay (keepalive socket maintains NAT mapping)
2. Quinn binds same port (`SO_REUSEPORT` allows coexistence)
3. Client discovers relay info from Modal Dict, registers, connects through relay
4. Relay forwards QUIC datagrams bidirectionally
5. Keepalive stops once QUIC connection is established

## Known Issues

- **End-to-end not yet verified.** The relay correctly forwards traffic between peers, but the full QUIC handshake through the relay has not completed successfully yet. The main challenge was NAT mapping expiration between the keepalive socket close and Quinn socket bind, which the `SO_REUSEPORT` change to quic-portal is intended to fix.
- **Requires quic-portal fork.** Upstream quic-portal does not set `SO_REUSEPORT` on Quinn's sockets, which is needed for the keepalive + Quinn coexistence.

## License

MIT License
