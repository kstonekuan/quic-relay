use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Registration prefix: peers send `REG:<session_uuid>\n` to join a session.
const REG_PREFIX: &[u8] = b"REG:";
/// Acknowledgement sent back after successful registration.
const ACK_RESPONSE: &[u8] = b"ACK\n";

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
}

impl Session {
    fn new(first_peer: SocketAddr) -> Self {
        Self {
            peers: [Some(first_peer), None],
            last_active: Instant::now(),
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

type SessionMap = Arc<Mutex<HashMap<String, Session>>>;

/// Reverse index: peer address → session ID for fast lookup on data packets.
type PeerIndex = Arc<Mutex<HashMap<SocketAddr, String>>>;

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
                    info!("Cleaned up stale session {session_id}");
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
    payload: &[u8],
) {
    let Ok(raw_session_id) = std::str::from_utf8(payload) else {
        warn!("Invalid UTF-8 in registration from {src_addr}");
        return;
    };

    let session_id = raw_session_id.trim().to_string();
    if session_id.is_empty() {
        warn!("Empty session ID from {src_addr}");
        return;
    }

    let mut sessions_guard = sessions.lock().await;
    let mut peer_index_guard = peer_index.lock().await;

    let session = sessions_guard.entry(session_id.clone()).or_insert_with(|| {
        info!("New session {session_id} created by {src_addr}");
        Session::new(src_addr)
    });

    match session.register(src_addr) {
        RegistrationResult::NewPeer => {
            info!("Peer {src_addr} joined session {session_id}");
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

    if let Some(dest_addr) = session.other_peer(src_addr) {
        drop(sessions_guard);
        if let Err(error) = socket.send_to(packet, dest_addr).await {
            warn!("Failed to forward to {dest_addr}: {error}");
        }
    } else {
        debug!("No peer to forward to for session {session_id} from {src_addr}");
    }
}

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
        let packet = &buf[..len];

        if packet.starts_with(REG_PREFIX) {
            let payload = &packet[REG_PREFIX.len()..];
            handle_registration(&socket, &sessions, &peer_index, src_addr, payload).await;
        } else {
            handle_data_forward(&socket, &sessions, &peer_index, src_addr, packet).await;
        }
    }
}
