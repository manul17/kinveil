//! Command-line argument and subcommand definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::state::{ServerArch, ServerRole, VpnProtocol};

#[derive(Parser, Debug)]
#[command(
    name = "kinveil",
    version,
    about = "Kinveil declarative, stateless manager and deployer"
)]
pub struct Cli {
    /// Path to encrypted state.enc file
    #[arg(long, global = true, env = "KINVEIL_STATE")]
    pub state: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a fresh encrypted state.enc
    Init {
        /// HTTPS subscription domain (e.g. sub.example.com)
        #[arg(long)]
        domain: Option<String>,
        /// Optional subscription URL base path override (defaults to random URL path)
        #[arg(long)]
        base_path: Option<String>,
    },
    /// Print redacted summary of state.enc
    Show,
    /// Validate vault state, config.toml, keys, certs, ports, and trial-render all configs
    Validate,
    /// View or edit global settings and protocol tuning presets (commented TOML in state.enc)
    Config {
        /// Print current config.toml to stdout without opening an editor
        #[arg(long, conflicts_with_all = ["file", "reset"])]
        print: bool,
        /// Replace config.toml from a local TOML file
        #[arg(long, value_name = "PATH", conflicts_with_all = ["print", "reset"])]
        file: Option<PathBuf>,
        /// Reset config.toml back to the built-in commented defaults
        #[arg(long, conflicts_with_all = ["print", "file"])]
        reset: bool,
        /// Skip interactive confirmation prompt when using --reset
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Update the HTTPS subscription domain (and optionally rotate the secret URL path)
    SetDomain {
        /// New HTTPS subscription domain (e.g. sub2.example.com)
        domain: String,
        /// Also regenerate the random secret URL base path
        #[arg(long)]
        rotate_base_path: bool,
    },
    /// Manage user credentials and subscriptions
    User {
        #[command(subcommand)]
        action: UserCommand,
    },
    /// Manage VPS nodes and protocol roles
    Server {
        #[command(subcommand)]
        action: ServerCommand,
    },
    /// Manage Cloudflare DNS automation settings stored inside state.enc
    Cloudflare {
        #[command(subcommand)]
        action: CloudflareCommand,
    },
    /// Converge servers, Cloudflare DNS, and HTTPS subscriptions to match state.enc
    Deploy {
        /// Plan changes locally without contacting remote servers, Cloudflare DNS, or HTTPS
        #[arg(long)]
        dry_run: bool,
        /// Target only a single server ID
        #[arg(long)]
        server: Option<String>,
        /// Skip Cloudflare DNS synchronization
        #[arg(long)]
        skip_dns: bool,
        /// Allow initial install on a server running conflicting web/proxy/firewall services
        #[arg(long)]
        takeover: bool,
        /// Skip interactive confirmation prompt when using --takeover
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Read-only health check (TCP + HTTPS by default; pass --ssh for remote systemd, UDP, and REALITY checks)
    Check {
        /// Check only a single server ID
        #[arg(long)]
        server: Option<String>,
        /// Also SSH into enabled servers to verify systemd units, UDP sockets, nftables, and REALITY target TLS 1.3 + H2
        #[arg(long)]
        ssh: bool,
    },
    /// Change the passphrase encrypting state.enc (without altering keys or credentials)
    Passwd,
    /// Copy encrypted state.enc (after verifying it decrypts) to a backup file
    Backup {
        /// Destination file path for the encrypted backup
        path: PathBuf,
    },
    /// Verify and restore an encrypted backup file over state.enc
    Restore {
        /// Encrypted backup file path to restore
        path: PathBuf,
        /// Skip interactive confirmation prompt before overwriting an existing state.enc
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Generate shell completions (bash, zsh, fish, elvish, powershell)
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Local bundle and subscription inspection helpers (no remote access)
    Debug {
        #[command(subcommand)]
        action: DebugCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum DebugCommand {
    /// Render every server bundle and decoded subscription into a directory
    Render {
        /// Output directory (must not exist; must live under /dev/shm on Linux unless --allow-non-tmpfs is set)
        dir: PathBuf,
        /// Allow writing rendered secrets outside RAM-backed /dev/shm tmpfs (for CI/macOS)
        #[arg(long)]
        allow_non_tmpfs: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// List configured users and credential status
    List,
    /// Add one or more users with freshly generated credentials
    Add {
        /// One or more usernames ([A-Za-z0-9._-]+)
        #[arg(required = true, num_args = 1..)]
        names: Vec<String>,
        /// Optional operator note (<= 256 characters)
        #[arg(long)]
        note: Option<String>,
    },
    /// Update metadata on an existing user
    Update {
        /// User name
        name: String,
        /// Updated operator note (pass "" to clear)
        #[arg(long)]
        note: Option<String>,
    },
    /// Enable access for a user
    Enable {
        /// User name
        name: String,
    },
    /// Disable access for a user without deleting credentials
    Disable {
        /// User name
        name: String,
    },
    /// Regenerate protocol credentials for a user (keeps UID/name/token by default)
    Rotate {
        /// User name
        name: String,
        /// Also rotate the subscription URL token
        #[arg(long = "rotate-url")]
        rotate_url: bool,
    },
    /// Permanently remove a user from desired state
    Remove {
        /// User name
        name: String,
        /// Skip interactive confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Print ready-to-send client setup instructions (URL, QR code, and Happ/Throne steps)
    Share {
        /// User name
        name: String,
        /// Print only the raw HTTPS subscription URL
        #[arg(long)]
        url_only: bool,
    },
    /// Print raw AmneziaWG client INI configuration
    #[command(name = "amneziawg-conf")]
    AmneziawgConf {
        /// User name
        name: String,
        /// Target VPN server ID (defaults to first enabled VPN server)
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServerCommand {
    /// List configured servers, roles, and effective ports
    List,
    /// Add a new Debian 12/13 VPS and generate its role keys/certificates/obfuscation
    Add(Box<ServerAddArgs>),
    /// Update roles, protocols, SNI, ports, metadata, or SSH settings on an existing server
    Update(Box<ServerUpdateArgs>),
    /// Rotate server protocol keys, TLS certificate, obfuscation, or SSH forwarding host key
    Rotate {
        /// Server ID
        id: String,
        /// Rotate all VPN protocol credentials (VLESS, Hysteria2, AmneziaWG, SSH forwarding)
        #[arg(long)]
        all: bool,
        /// Rotate VLESS REALITY keys, short ID, and XHTTP path
        #[arg(long)]
        vless: bool,
        /// Rotate Hysteria2 Salamander password and IP-SAN TLS keypair
        #[arg(long)]
        hysteria2: bool,
        /// Rotate AmneziaWG server keypair and obfuscation parameters
        #[arg(long)]
        amneziawg: bool,
        /// Rotate SSH forwarding server Ed25519 host key
        #[arg(long)]
        ssh_forwarding: bool,
    },
    /// Enable a server
    Enable {
        /// Server ID
        id: String,
    },
    /// Disable a server (omits from subscriptions; stops remote VPN services on deploy)
    Disable {
        /// Server ID
        id: String,
    },
    /// Remove a server from state
    Remove {
        /// Server ID
        id: String,
        /// SSH in first to stop managed services, delete vpnssh* users, and remove firewall rules
        #[arg(long)]
        wipe: bool,
        /// Skip interactive confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Args, Debug)]
pub struct ServerAddArgs {
    /// Public IPv4 address
    pub ipv4: String,
    /// Stable lowercase server ID (auto-derived from --label when omitted)
    #[arg(long)]
    pub id: Option<String>,
    /// Human-readable server label (e.g. "DE Germany")
    #[arg(long)]
    pub label: String,
    /// Comma-separated roles: vpn,subscription
    #[arg(long, value_enum, value_delimiter = ',', default_value = "vpn")]
    pub roles: Vec<ServerRole>,
    /// Comma-separated VPN protocols to enable (defaults to all four when omitted): vless,hysteria2,amneziawg,ssh-forwarding
    #[arg(long, value_enum, value_delimiter = ',')]
    pub protocols: Vec<VpnProtocol>,
    /// Camouflage SNI domain for VLESS REALITY (required when 'vpn' role is active)
    #[arg(long)]
    pub sni: Option<String>,
    /// Per-server VLESS+REALITY+XHTTP port override
    #[arg(long, help_heading = "Port Overrides")]
    pub vless_port: Option<u16>,
    /// Per-server Hysteria2 port override
    #[arg(long, help_heading = "Port Overrides")]
    pub hysteria2_port: Option<u16>,
    /// Per-server AmneziaWG port override
    #[arg(long, help_heading = "Port Overrides")]
    pub amneziawg_port: Option<u16>,
    /// Per-server SSH forwarding port override
    #[arg(long, help_heading = "Port Overrides")]
    pub ssh_forwarding_port: Option<u16>,
    /// Optional REALITY dialback target host:port (defaults to <sni>:443)
    #[arg(long, help_heading = "Advanced")]
    pub target: Option<String>,
    /// Optional XHTTP Host header override
    #[arg(long, help_heading = "Advanced")]
    pub xhttp_host: Option<String>,
    /// Optional public IPv6 address
    #[arg(long, help_heading = "Advanced")]
    pub ipv6: Option<String>,
    /// Admin SSH host override (defaults to public IPv4)
    #[arg(long, help_heading = "Advanced")]
    pub ssh_host: Option<String>,
    /// Admin SSH port
    #[arg(long, default_value_t = 22, help_heading = "Advanced")]
    pub ssh_port: u16,
    /// Admin SSH user
    #[arg(long, default_value = "root", help_heading = "Advanced")]
    pub ssh_user: String,
    /// Explicit OpenSSH host public key ('<type> <base64>')
    #[arg(long, help_heading = "Advanced")]
    pub ssh_host_key: Option<String>,
    /// Target server CPU architecture (deployment currently requires x86_64)
    #[arg(long, value_enum, default_value_t = ServerArch::X86_64, help_heading = "Advanced")]
    pub arch: ServerArch,
    /// Optional operator note (<= 256 characters)
    #[arg(long, help_heading = "Advanced")]
    pub note: Option<String>,
    /// Add server in disabled state initially
    #[arg(long, help_heading = "Advanced")]
    pub disabled: bool,
}

#[derive(Args, Debug)]
pub struct ServerUpdateArgs {
    /// Server ID
    pub id: String,
    /// Replace active server roles: vpn,subscription
    #[arg(long, value_enum, value_delimiter = ',')]
    pub roles: Option<Vec<ServerRole>>,
    /// Replace enabled VPN protocols on this server: vless,hysteria2,amneziawg,ssh-forwarding
    #[arg(long, value_enum, value_delimiter = ',')]
    pub protocols: Option<Vec<VpnProtocol>>,
    /// Camouflage SNI domain for VLESS REALITY (auto-resets target to <sni>:443 and clears xhttp-host unless passed in the same call)
    #[arg(long)]
    pub sni: Option<String>,
    /// Override REALITY dialback target host:port
    #[arg(long)]
    pub target: Option<String>,
    /// Override XHTTP Host header (pass "" to clear)
    #[arg(long)]
    pub xhttp_host: Option<String>,
    /// Per-server VLESS+REALITY+XHTTP port override
    #[arg(long, help_heading = "Port Overrides")]
    pub vless_port: Option<u16>,
    /// Per-server Hysteria2 port override
    #[arg(long, help_heading = "Port Overrides")]
    pub hysteria2_port: Option<u16>,
    /// Per-server AmneziaWG port override
    #[arg(long, help_heading = "Port Overrides")]
    pub amneziawg_port: Option<u16>,
    /// Per-server SSH forwarding port override
    #[arg(long, help_heading = "Port Overrides")]
    pub ssh_forwarding_port: Option<u16>,
    /// Clear existing port overrides before applying any new --*-port flags
    #[arg(long, help_heading = "Port Overrides")]
    pub clear_ports: bool,
    /// Updated human-readable server label
    #[arg(long)]
    pub label: Option<String>,
    /// Updated public IPv4 address (also syncs admin SSH host if previously equal to public IPv4 and refreshes Hysteria2 TLS cert)
    #[arg(long)]
    pub ipv4: Option<String>,
    /// Updated public IPv6 address
    #[arg(long, conflicts_with = "clear_ipv6")]
    pub ipv6: Option<String>,
    /// Remove the configured public IPv6 address
    #[arg(long, conflicts_with = "ipv6")]
    pub clear_ipv6: bool,
    /// Updated target CPU architecture
    #[arg(long, value_enum)]
    pub arch: Option<ServerArch>,
    /// Updated operator note (pass "" to clear)
    #[arg(long)]
    pub note: Option<String>,
    /// Updated admin SSH host
    #[arg(long)]
    pub ssh_host: Option<String>,
    /// Updated admin SSH port
    #[arg(long)]
    pub ssh_port: Option<u16>,
    /// Updated admin SSH user
    #[arg(long)]
    pub ssh_user: Option<String>,
    /// Updated OpenSSH host public key ('<type> <base64>'); re-scanned/looked up if SSH host or port changes
    #[arg(long)]
    pub ssh_host_key: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum CloudflareCommand {
    /// Configure Cloudflare DNS zone ID and API token (prompted securely, never via flags)
    Set {
        /// Cloudflare 32-hex-character Zone ID
        #[arg(long)]
        zone_id: String,
        /// DNS record TTL in seconds (1 = auto, or 60..=86400)
        #[arg(long, default_value_t = 60)]
        ttl: u32,
    },
    /// Remove Cloudflare DNS credentials from state.enc
    Clear,
}
