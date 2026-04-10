use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(
    name = "quic-relay",
    about = "UDP relay server for NAT traversal fallback"
)]
struct Args {
    /// UDP port to listen on.
    #[arg(long, default_value_t = 4433)]
    port: u16,

    /// Seconds of inactivity before a session is cleaned up.
    #[arg(long, default_value_t = 300)]
    session_timeout_secs: u64,
}

// ---------------------------------------------------------------------------
// Protocol: parsed message types at the UDP boundary
// ---------------------------------------------------------------------------

/// A parsed incoming UDP message. Produced once at the boundary; downstream
/// code works with typed variants instead of raw bytes.
enum RelayMessage<'a> {
    /// Peer registration: `REG:<session_id>\n`
    Registration { session_id: SessionId },
    /// Opaque datagram to be forwarded to the other peer in the session.
    Data { payload: &'a [u8] },
}

const REG_PREFIX: &[u8] = b"REG:";
const ACK_RESPONSE: &[u8] = b"ACK\n";

impl<'a> RelayMessage<'a> {
    /// Parse raw UDP packet into a typed message at the system boundary.
    fn parse(packet: &'a [u8]) -> Result<Self, &'static str> {
        if packet.starts_with(REG_PREFIX) {
            let payload = &packet[REG_PREFIX.len()..];
            let raw = std::str::from_utf8(payload).map_err(|_| "invalid UTF-8 in registration")?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err("empty session ID");
            }
            Ok(Self::Registration {
                session_id: SessionId(trimmed.to_string()),
            })
        } else {
            Ok(Self::Data { payload: packet })
        }
    }
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Opaque session identifier. Parsed from registration packets; prevents
/// accidental use of arbitrary strings as session keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SessionId(String);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Outcome of attempting to register a peer in a session.
enum RegistrationResult {
    /// Peer was already registered — no state change.
    AlreadyRegistered,
    /// Peer was added as the second participant.
    NewPeer,
    /// Session already has two peers — no room.
    SessionFull,
}

/// A relay session between two peers.
struct Session {
    /// Up to two peer addresses. Index 0 is the first registrant, 1 is the second.
    peers: [Option<SocketAddr>; 2],
    /// Last time any datagram was forwarded or a registration occurred.
    last_active: Instant,
    /// Number of datagrams forwarded in this session.
    forwarded_count: u64,
}

impl Session {
    fn new(first_peer: SocketAddr) -> Self {
        Self {
            peers: [Some(first_peer), None],
            last_active: Instant::now(),
            forwarded_count: 0,
        }
    }

    /// Returns both peer addresses if the session is fully paired.
    fn paired_peers(&self) -> Option<(SocketAddr, SocketAddr)> {
        match (self.peers[0], self.peers[1]) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }

    /// Register a peer in this session.
    fn register(&mut self, addr: SocketAddr) -> RegistrationResult {
        if self.peers[0] == Some(addr) || self.peers[1] == Some(addr) {
            self.last_active = Instant::now();
            return RegistrationResult::AlreadyRegistered;
        }
        if self.peers[1].is_none() {
            self.peers[1] = Some(addr);
            self.last_active = Instant::now();
            return RegistrationResult::NewPeer;
        }
        RegistrationResult::SessionFull
    }

    /// Given the sender's address, return the other peer's address (if registered).
    fn other_peer(&self, sender: SocketAddr) -> Option<SocketAddr> {
        if self.peers[0] == Some(sender) {
            self.peers[1]
        } else if self.peers[1] == Some(sender) {
            self.peers[0]
        } else {
            None
        }
    }
}

// The session ID is stored as both a key in SessionMap and a value in PeerIndex.
// This duplication is intentional: the reverse index enables O(1) lookup on
// every data packet (the hot path) without scanning all sessions.
type SessionMap = Arc<Mutex<HashMap<SessionId, Session>>>;
type PeerIndex = Arc<Mutex<HashMap<SocketAddr, SessionId>>>;

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

fn spawn_cleanup_task(sessions: SessionMap, peer_index: PeerIndex, session_timeout: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut sessions_guard = sessions.lock().await;
            let mut peer_index_guard = peer_index.lock().await;
            let before = sessions_guard.len();
            sessions_guard.retain(|session_id, session| {
                let alive = session.last_active.elapsed() < session_timeout;
                if !alive {
                    for addr in session.peers.iter().flatten() {
                        peer_index_guard.remove(addr);
                    }
                    info!(
                        "Cleaned up stale session {session_id} ({} datagrams forwarded)",
                        session.forwarded_count
                    );
                }
                alive
            });
            let removed = before - sessions_guard.len();
            if removed > 0 {
                info!(
                    "Cleanup: removed {removed} stale sessions, {} active",
                    sessions_guard.len()
                );
            }
        }
    });
}

async fn handle_registration(
    socket: &UdpSocket,
    sessions: &SessionMap,
    peer_index: &PeerIndex,
    src_addr: SocketAddr,
    session_id: SessionId,
) {
    let mut sessions_guard = sessions.lock().await;
    let mut peer_index_guard = peer_index.lock().await;

    let session = sessions_guard.entry(session_id.clone()).or_insert_with(|| {
        info!("New session {session_id} created by {src_addr}");
        Session::new(src_addr)
    });

    match session.register(src_addr) {
        RegistrationResult::NewPeer => {
            info!("Peer {src_addr} joined session {session_id}");
            if let Some((peer_a, peer_b)) = session.paired_peers() {
                info!("Session {session_id} active: {peer_a} <-> {peer_b}");
            }
        }
        RegistrationResult::AlreadyRegistered => {
            debug!("Peer {src_addr} re-registered for session {session_id}");
        }
        RegistrationResult::SessionFull => {
            warn!("Session {session_id} full, rejecting {src_addr}");
        }
    }

    peer_index_guard.insert(src_addr, session_id);

    drop(sessions_guard);
    drop(peer_index_guard);
    if let Err(error) = socket.send_to(ACK_RESPONSE, src_addr).await {
        warn!("Failed to send ACK to {src_addr}: {error}");
    }
}

async fn handle_data_forward(
    socket: &UdpSocket,
    sessions: &SessionMap,
    peer_index: &PeerIndex,
    src_addr: SocketAddr,
    packet: &[u8],
) {
    let peer_index_guard = peer_index.lock().await;
    let Some(session_id) = peer_index_guard.get(&src_addr).cloned() else {
        debug!("Data from unregistered peer {src_addr}, dropping");
        return;
    };
    drop(peer_index_guard);

    let mut sessions_guard = sessions.lock().await;
    let Some(session) = sessions_guard.get_mut(&session_id) else {
        debug!("Session {session_id} not found for {src_addr}, dropping");
        return;
    };

    session.last_active = Instant::now();
    session.forwarded_count += 1;
    let count = session.forwarded_count;

    if let Some(dest_addr) = session.other_peer(src_addr) {
        // Log first forward and then every 100th to avoid spam.
        if count == 1 {
            info!(
                "Session {session_id}: first datagram forwarded ({} bytes, {src_addr} -> {dest_addr})",
                packet.len()
            );
        } else if count % 100 == 0 {
            info!("Session {session_id}: {count} datagrams forwarded");
        }
        drop(sessions_guard);
        if let Err(error) = socket.send_to(packet, dest_addr).await {
            warn!("Failed to forward to {dest_addr}: {error}");
        }
    } else {
        debug!("No peer to forward to for session {session_id} from {src_addr}");
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    info!("UDP relay listening on {bind_addr}");

    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let peer_index: PeerIndex = Arc::new(Mutex::new(HashMap::new()));

    spawn_cleanup_task(
        sessions.clone(),
        peer_index.clone(),
        Duration::from_secs(args.session_timeout_secs),
    );

    let mut buf = vec![0u8; 65536];
    loop {
        let (len, src_addr) = socket.recv_from(&mut buf).await?;

        match RelayMessage::parse(&buf[..len]) {
            Ok(RelayMessage::Registration { session_id }) => {
                handle_registration(&socket, &sessions, &peer_index, src_addr, session_id).await;
            }
            Ok(RelayMessage::Data { payload }) => {
                handle_data_forward(&socket, &sessions, &peer_index, src_addr, payload).await;
            }
            Err(reason) => {
                warn!("Bad packet from {src_addr}: {reason}");
            }
        }
    }
}
