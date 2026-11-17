//! Command-line argument and subcommand definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::state::{ServerRole, VpnProtocol};

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
    /// View or edit global settings and protocol tuning (commented TOML in state.enc)
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
    /// Manage subscription domain, secret base path, and Cloudflare DNS settings
    Subscription {
        #[command(subcommand)]
        action: SubscriptionCommand,
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
    /// Query per-user and public NIC traffic totals for traffic-enabled servers
    Traffic {
        /// Start UTC date inclusive (YYYY-MM-DD; defaults to 1st of --to month)
        #[arg(long, value_name = "YYYY-MM-DD")]
        from: Option<String>,
        /// End UTC date inclusive (YYYY-MM-DD; defaults to today UTC)
        #[arg(long, value_name = "YYYY-MM-DD")]
        to: Option<String>,
        /// Query only a single server ID
        #[arg(long)]
        server: Option<String>,
        /// Show only a single user name
        #[arg(long)]
        user: Option<String>,
        /// Show per-protocol breakdown (vless, hysteria2, amneziawg, ssh-forwarding)
        #[arg(long)]
        by_protocol: bool,
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
pub enum SubscriptionCommand {
    /// Print subscription domain, host server, interval, routing, and Cloudflare DNS status
    Show {
        /// Also print compiled Happ and Throne routing deep links
        #[arg(long)]
        routing: bool,
    },
    /// Update the HTTPS subscription domain (and optionally rotate the secret URL path)
    SetDomain {
        /// New HTTPS subscription domain (e.g. sub2.example.com)
        domain: String,
        /// Also regenerate the random secret URL base path
        #[arg(long)]
        rotate_path: bool,
    },
    /// Set a custom secret URL base path or rotate to a freshly generated one
    SetPath {
        /// Explicit secret URL base path (must start and end with '/', >= 8 inner chars)
        #[arg(long, required_unless_present = "rotate", conflicts_with = "rotate")]
        path: Option<String>,
        /// Generate a fresh random secret URL base path
        #[arg(long, required_unless_present = "path", conflicts_with = "path")]
        rotate: bool,
    },
    /// Manage Cloudflare DNS automation settings stored inside state.enc
    Cloudflare {
        #[command(subcommand)]
        action: CloudflareCommand,
    },
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
    /// Update Cloudflare Zone ID or TTL without re-entering the API token
    Update {
        /// Updated Cloudflare 32-hex-character Zone ID
        #[arg(long)]
        zone_id: Option<String>,
        /// Updated DNS record TTL in seconds (1 = auto, or 60..=86400)
        #[arg(long)]
        ttl: Option<u32>,
    },
    /// Remove Cloudflare DNS credentials from state.enc
    Clear,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    Urls,
    Happ,
    Throne,
    Amneziawg,
    Ssh,
}

#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// List configured users and credential status
    List,
    /// Inspect detailed non-secret metadata and public keys for one user
    Show {
        /// User name
        name: String,
    },
    /// Add one or more users with freshly generated credentials
    Add {
        /// One or more usernames ([A-Za-z0-9._-]+)
        #[arg(required = true, num_args = 1..)]
        names: Vec<String>,
        /// Optional operator note (<= 256 characters)
        #[arg(long)]
        note: Option<String>,
        /// Add user(s) in disabled state initially
        #[arg(long)]
        disabled: bool,
    },
    /// Update name or metadata on an existing user
    Update {
        /// User name
        name: String,
        /// Rename the user key without changing UID, keys, or subscription URL
        #[arg(long)]
        rename: Option<String>,
        /// Updated operator note (<= 256 characters)
        #[arg(long, conflicts_with = "clear_note")]
        note: Option<String>,
        /// Remove the operator note
        #[arg(long, conflicts_with = "note")]
        clear_note: bool,
    },
    /// Enable access for one or more users
    Enable {
        /// User name(s)
        #[arg(required = true, num_args = 1..)]
        names: Vec<String>,
    },
    /// Disable access for one or more users without deleting credentials
    Disable {
        /// User name(s)
        #[arg(required = true, num_args = 1..)]
        names: Vec<String>,
    },
    /// Regenerate protocol credentials or subscription URL token for a user
    Rotate {
        /// User name
        name: String,
        /// Rotate all VPN protocol credentials (VLESS, Hysteria2, AmneziaWG, SSH forwarding)
        #[arg(long)]
        all: bool,
        /// Rotate VLESS UUID and spider_x
        #[arg(long)]
        vless: bool,
        /// Rotate Hysteria2 auth secret
        #[arg(long)]
        hysteria2: bool,
        /// Rotate AmneziaWG client keypair and preshared key
        #[arg(long)]
        amneziawg: bool,
        /// Rotate SSH forwarding client Ed25519 keypair
        #[arg(long)]
        ssh_forwarding: bool,
        /// Rotate the subscription URL token
        #[arg(long = "rotate-url")]
        rotate_url: bool,
    },
    /// Permanently remove one or more users from desired state
    Remove {
        /// User name(s)
        #[arg(required = true, num_args = 1..)]
        names: Vec<String>,
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
    /// Export raw protocol links, subscription payloads, AmneziaWG INI, or OpenSSH forwarding credentials
    Export {
        /// User name
        name: String,
        /// Output format (urls, happ, throne, amneziawg, ssh)
        #[arg(long, value_enum, default_value_t = ExportFormat::Urls)]
        format: ExportFormat,
        /// Filter by server ID (for urls, amneziawg, and ssh formats)
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServerCommand {
    /// List configured servers, roles, and effective ports
    List,
    /// Inspect detailed configuration, effective overrides, cert validity, and public keys for one server
    Show {
        /// Server ID
        id: String,
    },
    /// Add a new Debian 12/13 x86_64 VPS and generate its role keys/certificates/obfuscation
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
    /// Enable one or more servers
    Enable {
        /// Server ID(s)
        #[arg(required = true, num_args = 1..)]
        ids: Vec<String>,
    },
    /// Disable one or more servers (omits from subscriptions; stops remote VPN services on deploy)
    Disable {
        /// Server ID(s)
        #[arg(required = true, num_args = 1..)]
        ids: Vec<String>,
    },
    /// Remove one or more servers from state
    Remove {
        /// Server ID(s)
        #[arg(required = true, num_args = 1..)]
        ids: Vec<String>,
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
    /// Comma-separated VPN protocols override (inherits config.toml when omitted): vless,hysteria2,amneziawg,ssh-forwarding
    #[arg(long, value_enum, value_delimiter = ',')]
    pub protocols: Vec<VpnProtocol>,
    /// Camouflage SNI domain for VLESS REALITY (optional if [vless].sni is set in config.toml or VLESS is disabled)
    #[arg(long, help_heading = "VLESS REALITY")]
    pub vless_sni: Option<String>,
    /// Optional REALITY dialback target host:port (defaults to <vless-sni>:443)
    #[arg(long, help_heading = "VLESS REALITY")]
    pub vless_target: Option<String>,
    /// Optional XHTTP Host header override
    #[arg(long, help_heading = "VLESS REALITY")]
    pub vless_xhttp_host: Option<String>,
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
    /// Admin SSH host override (defaults to public IPv4)
    #[arg(long, help_heading = "Admin SSH")]
    pub ssh_host: Option<String>,
    /// Admin SSH port
    #[arg(long, default_value_t = 22, help_heading = "Admin SSH")]
    pub ssh_port: u16,
    /// Admin SSH user
    #[arg(long, default_value = "root", help_heading = "Admin SSH")]
    pub ssh_user: String,
    /// Optional OpenSSH private key path (-o IdentitiesOnly=yes -i <path>)
    #[arg(long, help_heading = "Admin SSH")]
    pub ssh_key: Option<String>,
    /// Explicit OpenSSH host public key ('<type> <base64>')
    #[arg(long, help_heading = "Admin SSH")]
    pub ssh_host_key: Option<String>,
    /// Optional public IPv6 address
    #[arg(long, help_heading = "Advanced")]
    pub ipv6: Option<String>,
    /// Optional operator note (<= 256 characters)
    #[arg(long, help_heading = "Advanced")]
    pub note: Option<String>,
    /// Add server in disabled state initially
    #[arg(long, help_heading = "Advanced")]
    pub disabled: bool,
    /// Enable daily UID-keyed traffic accounting on this server
    #[arg(long, help_heading = "Traffic Accounting")]
    pub traffic: bool,
}

#[derive(Args, Debug)]
pub struct ServerUpdateArgs {
    /// Server ID
    pub id: String,
    /// Rename the server ID in state.enc without regenerating keys or changing client subscriptions
    #[arg(long)]
    pub rename: Option<String>,
    /// Replace active server roles: vpn,subscription
    #[arg(long, value_enum, value_delimiter = ',')]
    pub roles: Option<Vec<ServerRole>>,
    /// Set explicit per-server VPN protocols (overrides config.toml defaults): vless,hysteria2,amneziawg,ssh-forwarding
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        conflicts_with = "clear_protocols"
    )]
    pub protocols: Option<Vec<VpnProtocol>>,
    /// Remove per-server VPN protocols override (inherits config.toml protocol enablement)
    #[arg(long, conflicts_with = "protocols")]
    pub clear_protocols: bool,
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
    /// Updated operator note (<= 256 characters)
    #[arg(long, conflicts_with = "clear_note")]
    pub note: Option<String>,
    /// Remove the operator note
    #[arg(long, conflicts_with = "note")]
    pub clear_note: bool,
    /// Camouflage SNI domain override for VLESS REALITY (auto-clears target/xhttp-host overrides unless passed together)
    #[arg(
        long,
        help_heading = "VLESS REALITY",
        conflicts_with = "clear_vless_sni"
    )]
    pub vless_sni: Option<String>,
    /// Remove per-server VLESS SNI override (falls back to [vless].sni in config.toml)
    #[arg(long, help_heading = "VLESS REALITY", conflicts_with = "vless_sni")]
    pub clear_vless_sni: bool,
    /// Override VLESS REALITY dialback target host:port
    #[arg(
        long,
        help_heading = "VLESS REALITY",
        conflicts_with = "clear_vless_target"
    )]
    pub vless_target: Option<String>,
    /// Remove per-server VLESS target override (falls back to [vless].target or <vless-sni>:443)
    #[arg(long, help_heading = "VLESS REALITY", conflicts_with = "vless_target")]
    pub clear_vless_target: bool,
    /// Override VLESS XHTTP Host header
    #[arg(
        long,
        help_heading = "VLESS REALITY",
        conflicts_with = "clear_vless_xhttp_host"
    )]
    pub vless_xhttp_host: Option<String>,
    /// Remove per-server VLESS XHTTP Host header override
    #[arg(
        long,
        help_heading = "VLESS REALITY",
        conflicts_with = "vless_xhttp_host"
    )]
    pub clear_vless_xhttp_host: bool,
    /// Per-server VLESS+REALITY+XHTTP port override
    #[arg(
        long,
        help_heading = "Port Overrides",
        conflicts_with = "clear_vless_port"
    )]
    pub vless_port: Option<u16>,
    /// Remove per-server VLESS port override
    #[arg(long, help_heading = "Port Overrides", conflicts_with = "vless_port")]
    pub clear_vless_port: bool,
    /// Per-server Hysteria2 port override
    #[arg(
        long,
        help_heading = "Port Overrides",
        conflicts_with = "clear_hysteria2_port"
    )]
    pub hysteria2_port: Option<u16>,
    /// Remove per-server Hysteria2 port override
    #[arg(
        long,
        help_heading = "Port Overrides",
        conflicts_with = "hysteria2_port"
    )]
    pub clear_hysteria2_port: bool,
    /// Per-server AmneziaWG port override
    #[arg(
        long,
        help_heading = "Port Overrides",
        conflicts_with = "clear_amneziawg_port"
    )]
    pub amneziawg_port: Option<u16>,
    /// Remove per-server AmneziaWG port override
    #[arg(
        long,
        help_heading = "Port Overrides",
        conflicts_with = "amneziawg_port"
    )]
    pub clear_amneziawg_port: bool,
    /// Per-server SSH forwarding port override
    #[arg(
        long,
        help_heading = "Port Overrides",
        conflicts_with = "clear_ssh_forwarding_port"
    )]
    pub ssh_forwarding_port: Option<u16>,
    /// Remove per-server SSH forwarding port override
    #[arg(
        long,
        help_heading = "Port Overrides",
        conflicts_with = "ssh_forwarding_port"
    )]
    pub clear_ssh_forwarding_port: bool,
    /// Clear all existing port overrides before applying any new --*-port flags
    #[arg(long, help_heading = "Port Overrides")]
    pub clear_ports: bool,
    /// Updated admin SSH host
    #[arg(long, help_heading = "Admin SSH")]
    pub ssh_host: Option<String>,
    /// Updated admin SSH port
    #[arg(long, help_heading = "Admin SSH")]
    pub ssh_port: Option<u16>,
    /// Updated admin SSH user
    #[arg(long, help_heading = "Admin SSH")]
    pub ssh_user: Option<String>,
    /// Updated OpenSSH private key path (-o IdentitiesOnly=yes -i <path>)
    #[arg(long, help_heading = "Admin SSH", conflicts_with = "clear_ssh_key")]
    pub ssh_key: Option<String>,
    /// Remove the configured admin SSH identity file path
    #[arg(long, help_heading = "Admin SSH", conflicts_with = "ssh_key")]
    pub clear_ssh_key: bool,
    /// Updated OpenSSH host public key ('<type> <base64>'); re-scanned/looked up if SSH host or port changes
    #[arg(long, help_heading = "Admin SSH")]
    pub ssh_host_key: Option<String>,
    /// Enable daily UID-keyed traffic accounting on this server
    #[arg(
        long,
        help_heading = "Traffic Accounting",
        conflicts_with = "no_traffic"
    )]
    pub traffic: bool,
    /// Disable daily UID-keyed traffic accounting on this server
    #[arg(long, help_heading = "Traffic Accounting", conflicts_with = "traffic")]
    pub no_traffic: bool,
}
