//! Entry point and terminal event loop for `socktop`.
//!
//! Supports `--once` for plain stdout snapshots and an interactive `ratatui` +
//! `crossterm` terminal view with filtering, sorting, scrolling, inspector toggle,
//! and pause controls.

mod net_sockets;
mod proc_map;
mod ui;

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::widgets::TableState;

use net_sockets::{
    SocketEntry, TcpState, display_state_for_proto, format_socket_addr, parse_proc_net_tcp,
    parse_proc_net_tcp6, parse_proc_net_udp, parse_proc_net_udp6,
};
use proc_map::{ProcessInfo, build_inode_map};
use ui::{UiSnapshot, draw_ui};

/// Command-line configuration controlling output mode and refresh cadence.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CliConfig {
    /// Prints a single plain-text table to stdout and exits when `true`.
    once: bool,
    /// Target refresh interval in milliseconds in interactive mode.
    interval_ms: u64,
}

impl Default for CliConfig {
    /// Defaults to interactive TUI mode refreshing once every 1000 ms.
    fn default() -> Self {
        Self {
            once: false,
            interval_ms: 1000,
        }
    }
}

/// Filter mode applied to socket entries before rendering the TUI table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketFilter {
    /// Shows all parsed sockets regardless of state.
    All,
    /// Shows only active `ESTABLISHED` connections.
    Established,
    /// Shows only `LISTEN` TCP sockets waiting for inbound connections.
    Listen,
    /// Shows only TCP sockets in `CLOSE-WAIT` where the remote side closed first.
    CloseWait,
    /// Shows only TCP sockets in `TIME-WAIT` waiting out `2 * MSL` after local close.
    TimeWait,
    /// Shows only unconnected (`UNCONN`, kernel `07` / `Close`) UDP sockets.
    Unconn,
}

impl SocketFilter {
    /// Cycles through state filters appropriate for the active protocol mode.
    fn next_for_proto(self, proto: ProtoFilter) -> Self {
        match proto {
            ProtoFilter::Udp => match self {
                Self::All => Self::Unconn,
                Self::Unconn => Self::All,
                // If arriving from a TCP-only state filter, jump straight to `Unconn`.
                _ => Self::Unconn,
            },
            ProtoFilter::All | ProtoFilter::Tcp => match self {
                Self::All => Self::Established,
                Self::Established => Self::Listen,
                Self::Listen => Self::CloseWait,
                Self::CloseWait => Self::TimeWait,
                Self::TimeWait => Self::All,
                Self::Unconn => Self::All,
            },
        }
    }

    /// Normalizes `self` when switching protocols so stale TCP-only states do not linger in UDP mode.
    fn sanitize_for_proto(self, proto: ProtoFilter) -> Self {
        match proto {
            ProtoFilter::Udp => match self {
                Self::All | Self::Unconn | Self::Established => self,
                // Drop TCP-only states (such as `LISTEN` or `TIME-WAIT`) when restricting to UDP.
                _ => Self::All,
            },
            ProtoFilter::All | ProtoFilter::Tcp => self,
        }
    }

    /// Short uppercase label shown in the header bar.
    fn label(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::Established => "ESTABLISHED",
            Self::Listen => "LISTEN",
            Self::CloseWait => "CLOSE-WAIT",
            Self::TimeWait => "TIME-WAIT",
            Self::Unconn => "UNCONN",
        }
    }

    /// Returns `true` when `entry` matches this filter mode.
    fn matches(self, entry: &SocketEntry) -> bool {
        match self {
            Self::All => true,
            Self::Established => entry.state == TcpState::Established,
            // Kernel `LISTEN` applies to TCP sockets; UDP sockets are connectionless.
            Self::Listen => {
                entry.proto != "udp" && entry.proto != "udp6" && entry.state == TcpState::Listen
            }
            Self::CloseWait => {
                !matches!(entry.proto, "udp" | "udp6") && entry.state == TcpState::CloseWait
            }
            Self::TimeWait => {
                !matches!(entry.proto, "udp" | "udp6") && entry.state == TcpState::TimeWait
            }
            // UDP sockets report unconnected state using kernel code `07` (`TcpState::Close`).
            Self::Unconn => matches!(entry.proto, "udp" | "udp6") && entry.state == TcpState::Close,
        }
    }
}

/// Protocol filter applied across IPv4 and IPv6 socket tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoFilter {
    /// Shows all supported protocols (`tcp`, `tcp6`, `udp`, `udp6`).
    All,
    /// Shows only TCP sockets (`tcp` and `tcp6`).
    Tcp,
    /// Shows only UDP sockets (`udp` and `udp6`).
    Udp,
}

impl ProtoFilter {
    /// Cycles through protocol filter modes when pressing `p`.
    fn next(self) -> Self {
        match self {
            Self::All => Self::Tcp,
            Self::Tcp => Self::Udp,
            Self::Udp => Self::All,
        }
    }

    /// Short uppercase label shown in the TUI header bar.
    fn label(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }

    /// Returns `true` when `entry.proto` matches this protocol filter.
    fn matches(self, entry: &SocketEntry) -> bool {
        match self {
            Self::All => true,
            Self::Tcp => matches!(entry.proto, "tcp" | "tcp6"),
            Self::Udp => matches!(entry.proto, "udp" | "udp6"),
        }
    }
}

/// Column sorting mode applied to filtered socket rows in the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortMode {
    /// Preserves the order returned by `/proc/net/*`.
    None,
    /// Sorts numerically by local port number.
    LocalPort,
    /// Sorts numerically by remote port number.
    RemotePort,
    /// Sorts by owning PID (unmapped sockets sort last).
    Pid,
}

impl SortMode {
    /// Cycles through sort modes when pressing `s`.
    fn next(self) -> Self {
        match self {
            Self::None => Self::LocalPort,
            Self::LocalPort => Self::RemotePort,
            Self::RemotePort => Self::Pid,
            Self::Pid => Self::None,
        }
    }

    /// Short uppercase label shown in the header bar.
    fn label(self) -> &'static str {
        match self {
            Self::None => "DEFAULT",
            Self::LocalPort => "LOCAL-PORT",
            Self::RemotePort => "REMOTE-PORT",
            Self::Pid => "PID",
        }
    }
}

/// Sorts socket entries in place according to `mode`, breaking ties deterministically by `inode`.
fn sort_sockets(sockets: &mut [SocketEntry], proc_map: &HashMap<u64, ProcessInfo>, mode: SortMode) {
    match mode {
        SortMode::None => {}
        SortMode::LocalPort => {
            sockets.sort_by(|a, b| {
                a.local_addr
                    .port()
                    .cmp(&b.local_addr.port())
                    .then_with(|| a.inode.cmp(&b.inode))
            });
        }
        SortMode::RemotePort => {
            sockets.sort_by(|a, b| {
                a.remote_addr
                    .port()
                    .cmp(&b.remote_addr.port())
                    .then_with(|| a.inode.cmp(&b.inode))
            });
        }
        SortMode::Pid => {
            sockets.sort_by(|a, b| {
                // Map missing PIDs to `u32::MAX` so unowned/TIME-WAIT rows sit at the bottom.
                let pid_a = proc_map.get(&a.inode).map_or(u32::MAX, |p| p.pid);
                let pid_b = proc_map.get(&b.inode).map_or(u32::MAX, |p| p.pid);
                pid_a.cmp(&pid_b).then_with(|| a.inode.cmp(&b.inode))
            });
        }
    }
}

/// Descriptor for a `/proc/net/*` table file and its line parser.
struct SocketSource {
    /// Filesystem path to the `/proc/net/*` pseudo-file.
    path: &'static str,
    /// Parser function invoked for this socket table.
    parser: fn(&Path) -> io::Result<Vec<SocketEntry>>,
}

/// Collects IPv4/IPv6 TCP and UDP sockets in one sequential pass per tick.
fn load_all_sockets() -> io::Result<Vec<SocketEntry>> {
    let sources = [
        SocketSource {
            path: "/proc/net/tcp",
            parser: parse_proc_net_tcp,
        },
        SocketSource {
            path: "/proc/net/tcp6",
            parser: parse_proc_net_tcp6,
        },
        SocketSource {
            path: "/proc/net/udp",
            parser: parse_proc_net_udp,
        },
        SocketSource {
            path: "/proc/net/udp6",
            parser: parse_proc_net_udp6,
        },
    ];

    let mut sockets = Vec::new();
    for source in sources {
        match (source.parser)(Path::new(source.path)) {
            Ok(mut entries) => sockets.append(&mut entries),
            // Optional protocol tables (such as IPv6 or UDP when disabled) may be absent.
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }

    Ok(sockets)
}

/// Parses command-line flags from any string iterator for easy unit testing.
fn parse_args<I>(args: I) -> Result<CliConfig, String>
where
    I: IntoIterator<Item = String>,
{
    let mut cfg = CliConfig::default();
    // Skip `args[0]` (executable name).
    let mut iter = args.into_iter().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--once" => cfg.once = true,
            "--interval-ms" => {
                let Some(val) = iter.next() else {
                    return Err("--interval-ms requires a value".to_string());
                };
                let parsed = val
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --interval-ms value '{val}'"))?;
                // Zero would cause `event::poll` to spin immediately with a zero timeout.
                if parsed == 0 {
                    return Err("--interval-ms must be greater than 0".to_string());
                }
                cfg.interval_ms = parsed;
            }
            "--help" | "-h" => {
                return Err("usage: socktop [--once] [--interval-ms <ms>]".to_string());
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }

    Ok(cfg)
}

/// Formats active sockets and matched process names into a plain-text table for `--once`.
fn format_socket_table(sockets: &[SocketEntry], proc_map: &HashMap<u64, ProcessInfo>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<6} {:<12} {:<22} {:<22} {:<8} {}\n",
        "PROTO", "STATE", "LOCAL", "REMOTE", "PID", "PROCESS"
    ));
    out.push_str(&format!("{}\n", "-".repeat(82)));

    for sock in sockets {
        // Kernel-held sockets (such as TIME-WAIT) or restricted PIDs may lack a mapping.
        let (pid_str, proc_name) = match proc_map.get(&sock.inode) {
            Some(info) => (info.pid.to_string(), info.name.as_str()),
            None => ("-".to_string(), "-"),
        };

        out.push_str(&format!(
            "{:<6} {:<12} {:<22} {:<22} {:<8} {}\n",
            sock.proto,
            display_state_for_proto(sock.proto, sock.state),
            format_socket_addr(sock.local_addr),
            format_socket_addr(sock.remote_addr),
            pid_str,
            proc_name,
        ));
    }

    out
}

/// Prints a single plain-text snapshot to stdout.
fn print_once() -> io::Result<()> {
    let sockets = load_all_sockets()?;
    let proc_map = build_inode_map()?;
    let rendered = format_socket_table(&sockets, &proc_map);

    // Lock stdout for a single buffered write and flush before exiting.
    let mut stdout = io::stdout().lock();
    write!(stdout, "{rendered}")?;
    stdout.flush()
}

/// Restores normal terminal mode and leaves the alternate screen buffer.
fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

/// Runs the interactive TUI loop until the user quits (`q` or `Ctrl+C`) or an I/O error occurs.
fn run_tui(interval_ms: u64) -> io::Result<()> {
    // Enter raw mode and alternate screen before starting the event loop.
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, Duration::from_millis(interval_ms));

    // Always attempt cleanup even if `event_loop` returned an error.
    let cleanup_res = restore_terminal(&mut terminal);
    result.and(cleanup_res)
}

/// Adjusts the selected row index so it stays valid for a slice of length `len`.
fn clamp_selection(table_state: &mut TableState, len: usize) {
    if len == 0 {
        table_state.select(None);
        return;
    }

    match table_state.selected() {
        Some(idx) if idx >= len => table_state.select(Some(len - 1)),
        Some(_) => {}
        // Select the first row automatically when a non-empty list has no selection yet.
        None => table_state.select(Some(0)),
    }
}

/// Moves row selection up or down by `delta` (`+1` down, `-1` up) within `0..len`.
fn move_selection(table_state: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        table_state.select(None);
        return;
    }

    let current = table_state.selected().unwrap_or(0) as isize;
    // Clamp into `0..len` so holding `j`/`k` or arrow keys never wraps or out-of-bounds indices.
    let next = (current + delta).clamp(0, (len - 1) as isize) as usize;
    table_state.select(Some(next));
}

/// Returns `true` when `entry` matches `query` (case-insensitive) across process, address, port, proto, or state.
fn matches_search(entry: &SocketEntry, proc_map: &HashMap<u64, ProcessInfo>, query: &str) -> bool {
    let needle = query.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }

    let proc_match = proc_map.get(&entry.inode).is_some_and(|info| {
        info.name.to_ascii_lowercase().contains(&needle) || info.pid.to_string().contains(&needle)
    });

    let local_ip = entry.local_addr.ip().to_string().to_ascii_lowercase();
    let remote_ip = entry.remote_addr.ip().to_string().to_ascii_lowercase();
    let local_port = entry.local_addr.port().to_string();
    let remote_port = entry.remote_addr.port().to_string();
    let state_str = display_state_for_proto(entry.proto, entry.state).to_ascii_lowercase();

    // Match exact port numbers so e.g. `"80"` does not falsely match port `"8080"`.
    proc_match
        || local_ip.contains(&needle)
        || remote_ip.contains(&needle)
        || local_port == needle
        || remote_port == needle
        || entry.proto.to_ascii_lowercase().contains(&needle)
        || state_str.contains(&needle)
}

/// Returns a cloned list of sockets matching `state_filter`, `proto_filter`, and `search_query`.
fn apply_filters(
    sockets: &[SocketEntry],
    proc_map: &HashMap<u64, ProcessInfo>,
    state_filter: SocketFilter,
    proto_filter: ProtoFilter,
    search_query: &str,
) -> Vec<SocketEntry> {
    sockets
        .iter()
        .filter(|entry| {
            state_filter.matches(entry)
                && proto_filter.matches(entry)
                && matches_search(entry, proc_map, search_query)
        })
        .cloned()
        .collect()
}

/// Rebuilds `visible_sockets` from `all_sockets` using active filters, search, sort mode, and selection clamping.
fn refresh_visible_sockets(
    all_sockets: &[SocketEntry],
    proc_map: &HashMap<u64, ProcessInfo>,
    state_filter: SocketFilter,
    proto_filter: ProtoFilter,
    search_query: &str,
    sort_mode: SortMode,
    table_state: &mut TableState,
) -> Vec<SocketEntry> {
    let mut visible = apply_filters(
        all_sockets,
        proc_map,
        state_filter,
        proto_filter,
        search_query,
    );
    sort_sockets(&mut visible, proc_map, sort_mode);
    // Keep the cursor inside bounds whenever filtering or live refresh shrinks the row count.
    clamp_selection(table_state, visible.len());
    visible
}

/// Polls keyboard input and refreshes `/proc` socket snapshots on a fixed cadence.
fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    interval: Duration,
) -> io::Result<()> {
    let mut all_sockets = load_all_sockets()?;
    let mut proc_map = build_inode_map()?;
    let mut filter = SocketFilter::All;
    let mut proto_filter = ProtoFilter::All;
    let mut sort_mode = SortMode::None;
    let mut searching = false;
    let mut search_query = String::new();
    let mut paused = false;
    let mut last_tick = Instant::now();
    let mut table_state = TableState::default();
    let mut show_inspector = false;

    let mut visible_sockets = refresh_visible_sockets(
        &all_sockets,
        &proc_map,
        filter,
        proto_filter,
        &search_query,
        sort_mode,
        &mut table_state,
    );
    clamp_selection(&mut table_state, visible_sockets.len());

    loop {
        terminal.draw(|frame| {
            let selected_socket = table_state
                .selected()
                .and_then(|idx| visible_sockets.get(idx));

            let snap = UiSnapshot {
                sockets: &visible_sockets,
                proc_map: &proc_map,
                interval_ms: interval.as_millis() as u64,
                paused,
                filter_label: filter.label(),
                proto_label: proto_filter.label(),
                sort_label: sort_mode.label(),
                search_query: &search_query,
                searching,
                show_inspector,
                selected_socket,
            };
            draw_ui(frame, &snap, &mut table_state);
        })?;

        // Poll only for the remaining time until the next scheduled refresh tick.
        let elapsed = last_tick.elapsed();
        let timeout = interval.saturating_sub(elapsed);

        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if searching {
                // Route keystrokes to search input editing while `/` search mode is active.
                match key.code {
                    KeyCode::Esc => {
                        search_query.clear();
                        searching = false;
                        visible_sockets = refresh_visible_sockets(
                            &all_sockets,
                            &proc_map,
                            filter,
                            proto_filter,
                            &search_query,
                            sort_mode,
                            &mut table_state,
                        );
                    }
                    KeyCode::Enter => {
                        searching = false;
                    }
                    KeyCode::Backspace => {
                        search_query.pop();
                        visible_sockets = refresh_visible_sockets(
                            &all_sockets,
                            &proc_map,
                            filter,
                            proto_filter,
                            &search_query,
                            sort_mode,
                            &mut table_state,
                        );
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        search_query.push(c);
                        visible_sockets = refresh_visible_sockets(
                            &all_sockets,
                            &proc_map,
                            filter,
                            proto_filter,
                            &search_query,
                            sort_mode,
                            &mut table_state,
                        );
                    }
                    _ => {}
                }
            } else {
                // Handle global navigation, filter, sort, inspector, and quit commands.
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Char('/') => {
                        searching = true;
                    }
                    KeyCode::Esc if !search_query.is_empty() => {
                        search_query.clear();
                        visible_sockets = refresh_visible_sockets(
                            &all_sockets,
                            &proc_map,
                            filter,
                            proto_filter,
                            &search_query,
                            sort_mode,
                            &mut table_state,
                        );
                    }
                    KeyCode::Char(' ') => paused = !paused,
                    KeyCode::Char('f') => {
                        filter = filter.next_for_proto(proto_filter);
                        visible_sockets = refresh_visible_sockets(
                            &all_sockets,
                            &proc_map,
                            filter,
                            proto_filter,
                            &search_query,
                            sort_mode,
                            &mut table_state,
                        );
                    }
                    KeyCode::Char('p') => {
                        proto_filter = proto_filter.next();
                        filter = filter.sanitize_for_proto(proto_filter);
                        visible_sockets = refresh_visible_sockets(
                            &all_sockets,
                            &proc_map,
                            filter,
                            proto_filter,
                            &search_query,
                            sort_mode,
                            &mut table_state,
                        );
                    }
                    KeyCode::Char('s') => {
                        sort_mode = sort_mode.next();
                        visible_sockets = refresh_visible_sockets(
                            &all_sockets,
                            &proc_map,
                            filter,
                            proto_filter,
                            &search_query,
                            sort_mode,
                            &mut table_state,
                        );
                    }
                    KeyCode::Up | KeyCode::Char('j') => {
                        move_selection(&mut table_state, visible_sockets.len(), -1);
                    }
                    KeyCode::Down | KeyCode::Char('k') => {
                        move_selection(&mut table_state, visible_sockets.len(), 1);
                    }
                    KeyCode::Char('i') => {
                        show_inspector = !show_inspector;
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= interval {
            // Reset `last_tick` every interval even while paused so unpausing starts a fresh period.
            last_tick = Instant::now();
            if !paused {
                all_sockets = load_all_sockets()?;
                proc_map = build_inode_map()?;
                visible_sockets = refresh_visible_sockets(
                    &all_sockets,
                    &proc_map,
                    filter,
                    proto_filter,
                    &search_query,
                    sort_mode,
                    &mut table_state,
                );
            }
        }
    }
}

/// Parses CLI arguments and runs either the one-shot stdout mode or the interactive TUI.
fn main() {
    let cfg = match parse_args(std::env::args()) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{msg}");
            // Exit code `2` signals invalid CLI usage or `--help` output.
            std::process::exit(2);
        }
    };

    let run_res = if cfg.once {
        print_once()
    } else {
        run_tui(cfg.interval_ms)
    };

    if let Err(err) = run_res {
        eprintln!("error: {err}");
        // Exit code `1` signals runtime/I/O failures during snapshot or TUI execution.
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    // Build a baseline loopback TCP socket fixture for filter, sort, and search tests.
    fn sample_socket(port: u16, state: TcpState, inode: u64) -> SocketEntry {
        SocketEntry {
            proto: "tcp",
            local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)),
            remote_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
            state,
            uid: 1000,
            inode,
        }
    }

    #[test]
    fn parses_cli_flags_cleanly() {
        let args = vec![
            "socktop".to_string(),
            "--once".to_string(),
            "--interval-ms".to_string(),
            "500".to_string(),
        ];
        let cfg = parse_args(args).expect("expected valid CLI args");
        assert_eq!(
            cfg,
            CliConfig {
                once: true,
                interval_ms: 500
            }
        );
    }

    #[test]
    fn rejects_invalid_interval() {
        // Zero poll timeout is rejected so the event loop cannot busy-spin.
        let args = vec![
            "socktop".to_string(),
            "--interval-ms".to_string(),
            "0".to_string(),
        ];
        assert!(parse_args(args).is_err());
    }

    #[test]
    fn formats_rows_with_and_without_pid() {
        let sockets = vec![sample_socket(8080, TcpState::Listen, 555)];
        let mut map = HashMap::new();
        map.insert(
            555,
            ProcessInfo {
                pid: 1200,
                name: "python3".to_string(),
            },
        );

        let table = format_socket_table(&sockets, &map);
        assert!(table.contains("LISTEN"));
        assert!(table.contains("127.0.0.1:8080"));
        assert!(table.contains("1200"));
        assert!(table.contains("python3"));
    }

    #[test]
    fn cycles_and_applies_socket_filters() {
        let mut udp_est = sample_socket(5353, TcpState::Established, 5);
        udp_est.proto = "udp";

        let sockets = vec![
            sample_socket(80, TcpState::Listen, 1),
            sample_socket(51234, TcpState::Established, 2),
            sample_socket(51235, TcpState::TimeWait, 3),
            sample_socket(51236, TcpState::CloseWait, 4),
            udp_est,
        ];
        let proc_map = HashMap::new();

        // `All` filter and protocol keeps all five entries.
        assert_eq!(
            apply_filters(&sockets, &proc_map, SocketFilter::All, ProtoFilter::All, "").len(),
            5
        );

        // `Established` across all protocols matches both TCP (inode 2) and UDP (inode 5).
        let est = apply_filters(
            &sockets,
            &proc_map,
            SocketFilter::Established,
            ProtoFilter::All,
            "",
        );
        assert_eq!(est.len(), 2);

        // Combining `Established` with `ProtoFilter::Udp` narrows to only the UDP socket.
        let udp_est_only = apply_filters(
            &sockets,
            &proc_map,
            SocketFilter::Established,
            ProtoFilter::Udp,
            "",
        );
        assert_eq!(udp_est_only.len(), 1);
        assert_eq!(udp_est_only[0].local_addr.port(), 5353);

        let listen = apply_filters(
            &sockets,
            &proc_map,
            SocketFilter::Listen,
            ProtoFilter::All,
            "",
        );
        assert_eq!(listen.len(), 1);
        assert_eq!(listen[0].local_addr.port(), 80);

        let close_wait = apply_filters(
            &sockets,
            &proc_map,
            SocketFilter::CloseWait,
            ProtoFilter::All,
            "",
        );
        assert_eq!(close_wait.len(), 1);
        assert_eq!(close_wait[0].local_addr.port(), 51236);

        let tw = apply_filters(
            &sockets,
            &proc_map,
            SocketFilter::TimeWait,
            ProtoFilter::All,
            "",
        );
        assert_eq!(tw.len(), 1);
        assert_eq!(tw[0].local_addr.port(), 51235);

        // Five steps from `All` in `All`/`Tcp` mode completes a full filter cycle back to `All`.
        assert_eq!(
            SocketFilter::All
                .next_for_proto(ProtoFilter::All)
                .next_for_proto(ProtoFilter::All)
                .next_for_proto(ProtoFilter::All)
                .next_for_proto(ProtoFilter::All)
                .next_for_proto(ProtoFilter::All),
            SocketFilter::All
        );
    }

    #[test]
    fn cycles_state_filters_according_to_protocol() {
        // In UDP mode, `f` toggles cleanly between `All` and `Unconn`.
        assert_eq!(
            SocketFilter::All.next_for_proto(ProtoFilter::Udp),
            SocketFilter::Unconn
        );
        assert_eq!(
            SocketFilter::Unconn.next_for_proto(ProtoFilter::Udp),
            SocketFilter::All
        );
        // Arriving from a TCP-specific state jumps straight to `Unconn`.
        assert_eq!(
            SocketFilter::TimeWait.next_for_proto(ProtoFilter::Udp),
            SocketFilter::Unconn
        );

        // In TCP/All mode, cycling visits TCP states and loops back to `All`.
        assert_eq!(
            SocketFilter::All.next_for_proto(ProtoFilter::Tcp),
            SocketFilter::Established
        );
        assert_eq!(
            SocketFilter::TimeWait.next_for_proto(ProtoFilter::Tcp),
            SocketFilter::All
        );
    }

    #[test]
    fn sanitizes_tcp_only_state_filters_when_entering_udp() {
        // TCP-only states reset to `All` when switching into `ProtoFilter::Udp`.
        assert_eq!(
            SocketFilter::Listen.sanitize_for_proto(ProtoFilter::Udp),
            SocketFilter::All
        );
        assert_eq!(
            SocketFilter::CloseWait.sanitize_for_proto(ProtoFilter::Udp),
            SocketFilter::All
        );
        assert_eq!(
            SocketFilter::TimeWait.sanitize_for_proto(ProtoFilter::Udp),
            SocketFilter::All
        );

        // States valid for UDP remain intact.
        assert_eq!(
            SocketFilter::All.sanitize_for_proto(ProtoFilter::Udp),
            SocketFilter::All
        );
        assert_eq!(
            SocketFilter::Unconn.sanitize_for_proto(ProtoFilter::Udp),
            SocketFilter::Unconn
        );
        assert_eq!(
            SocketFilter::Established.sanitize_for_proto(ProtoFilter::Udp),
            SocketFilter::Established
        );
    }

    #[test]
    fn matches_unconn_only_for_unconnected_udp_and_udp6_sockets() {
        let mut udp_unconn = sample_socket(5353, TcpState::Close, 21);
        udp_unconn.proto = "udp";

        let mut udp6_unconn = sample_socket(546, TcpState::Close, 22);
        udp6_unconn.proto = "udp6";

        let mut udp_established = sample_socket(9000, TcpState::Established, 23);
        udp_established.proto = "udp";

        // Raw `TcpState::Close` on a `tcp` socket must not match `SocketFilter::Unconn`.
        let tcp_closed = sample_socket(8080, TcpState::Close, 24);

        let sockets = vec![udp_unconn, udp6_unconn, udp_established, tcp_closed];
        let proc_map = HashMap::new();
        let filtered = apply_filters(
            &sockets,
            &proc_map,
            SocketFilter::Unconn,
            ProtoFilter::Udp,
            "",
        );

        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].inode, 21);
        assert_eq!(filtered[1].inode, 22);
    }

    #[test]
    fn clamps_selection_when_filter_shrinks_rows() {
        let mut state = TableState::default();
        state.select(Some(4));
        // Clamp out-of-range index `4` down to the last valid index `1` for length `2`.
        clamp_selection(&mut state, 2);
        assert_eq!(state.selected(), Some(1));

        // Clear selection when no rows remain visible.
        clamp_selection(&mut state, 0);
        assert_eq!(state.selected(), None);
    }

    #[test]
    fn sorts_sockets_by_port_and_pid() {
        let mut sockets = vec![
            SocketEntry {
                proto: "tcp",
                local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
                remote_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443)),
                state: TcpState::Established,
                uid: 1000,
                inode: 20,
            },
            SocketEntry {
                proto: "tcp",
                local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 53)),
                remote_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80)),
                state: TcpState::Listen,
                uid: 1000,
                inode: 10,
            },
        ];

        // Only inode `20` has a mapped PID; inode `10` maps to `u32::MAX` and sorts after it.
        let mut proc_map = HashMap::new();
        proc_map.insert(
            20,
            ProcessInfo {
                pid: 100,
                name: "app".to_string(),
            },
        );

        sort_sockets(&mut sockets, &proc_map, SortMode::LocalPort);
        assert_eq!(sockets[0].local_addr.port(), 53);
        assert_eq!(sockets[1].local_addr.port(), 8080);

        sort_sockets(&mut sockets, &proc_map, SortMode::RemotePort);
        assert_eq!(sockets[0].remote_addr.port(), 80);
        assert_eq!(sockets[1].remote_addr.port(), 443);

        sort_sockets(&mut sockets, &proc_map, SortMode::Pid);
        assert_eq!(sockets[0].inode, 20);
        assert_eq!(sockets[1].inode, 10);
    }

    #[test]
    fn filters_sockets_by_protocol() {
        let mut tcp6_sock = sample_socket(443, TcpState::Established, 10);
        tcp6_sock.proto = "tcp6";

        let mut udp_sock = sample_socket(5353, TcpState::Close, 11);
        udp_sock.proto = "udp";

        let mut udp6_sock = sample_socket(546, TcpState::Close, 12);
        udp6_sock.proto = "udp6";

        let sockets = vec![
            sample_socket(80, TcpState::Listen, 9),
            tcp6_sock,
            udp_sock,
            udp6_sock,
        ];
        let proc_map = HashMap::new();
        let tcp_only = apply_filters(&sockets, &proc_map, SocketFilter::All, ProtoFilter::Tcp, "");
        assert_eq!(tcp_only.len(), 2);
        assert!(tcp_only.iter().all(|s| matches!(s.proto, "tcp" | "tcp6")));

        let udp_only = apply_filters(&sockets, &proc_map, SocketFilter::All, ProtoFilter::Udp, "");
        assert_eq!(udp_only.len(), 2);
        assert!(udp_only.iter().all(|s| matches!(s.proto, "udp" | "udp6")));
    }

    #[test]
    fn matches_search_by_process_exact_port_and_case() {
        let sock_80 = sample_socket(80, TcpState::Listen, 100);
        let sock_8080 = sample_socket(8080, TcpState::Established, 200);

        let mut proc_map = HashMap::new();
        proc_map.insert(
            200,
            ProcessInfo {
                pid: 4242,
                name: "NginxWorker".to_string(),
            },
        );

        assert!(matches_search(&sock_80, &proc_map, ""));
        assert!(matches_search(&sock_80, &proc_map, "80"));
        assert!(!matches_search(&sock_8080, &proc_map, "80"));
        assert!(matches_search(&sock_8080, &proc_map, "8080"));
        assert!(matches_search(&sock_8080, &proc_map, "nginx"));
        assert!(matches_search(&sock_8080, &proc_map, "4242"));
    }

    #[test]
    fn matches_search_finds_ipv4_mapped_ipv6_by_ipv4_address() {
        let mut mapped_sock = sample_socket(8443, TcpState::Established, 300);
        mapped_sock.proto = "tcp6";
        mapped_sock.local_addr = "[::ffff:192.168.1.42]:8443".parse().unwrap();
        mapped_sock.remote_addr = "[::ffff:10.0.0.15]:51514".parse().unwrap();

        let proc_map = HashMap::new();

        // Matches normalized IPv4 addresses or prefixes on both local and remote sides.
        assert!(matches_search(&mapped_sock, &proc_map, "192.168.1.42"));
        assert!(matches_search(&mapped_sock, &proc_map, "192.168.1."));
        assert!(matches_search(&mapped_sock, &proc_map, "10.0.0.15"));
        assert!(matches_search(&mapped_sock, &proc_map, "tcp6"));

        // Does not falsely match a different IPv4 address or a port substring like "844".
        assert!(!matches_search(&mapped_sock, &proc_map, "192.168.1.99"));
        assert!(!matches_search(&mapped_sock, &proc_map, "844"));
    }
}
