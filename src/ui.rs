//! Terminal user interface rendering for `socktop` using `ratatui`.
//!
//! Keeps drawing logic separate from `/proc` parsing and event handling so layout
//! changes stay isolated in one place.

use std::collections::HashMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};

use crate::net_sockets::{SocketEntry, TcpState, display_state_for_proto, format_socket_addr};
use crate::proc_map::ProcessInfo;

/// Read-only view data passed into [`draw_ui`] on each frame.
pub struct UiSnapshot<'a> {
    /// Socket entries to display (already filtered if an active filter is set).
    pub sockets: &'a [SocketEntry],
    /// Lookup map from socket inode to owning PID and command name.
    pub proc_map: &'a HashMap<u64, ProcessInfo>,
    /// Refresh cadence in milliseconds, shown in the header bar.
    pub interval_ms: u64,
    /// When `true`, new `/proc` snapshots are paused while the UI remains interactive.
    pub paused: bool,
    /// Label describing the active TCP state filter (such as `"ALL"` or `"LISTEN"`).
    pub filter_label: &'a str,
    /// Label describing the active protocol filter (such as `"ALL"`, `"TCP"`, or `"UDP"`).
    pub proto_label: &'a str,
    /// Label describing the active sorting mode (such as `"DEFAULT"` or `"PID"`).
    pub sort_label: &'a str,
    /// Active live search query string (empty when no search filter is set).
    pub search_query: &'a str,
    /// `true` while the user is actively typing into the search prompt.
    pub searching: bool,
    /// When `true`, renders the side/bottom socket detail inspector pane (`[i]`).
    pub show_inspector: bool,
    /// Currently highlighted socket entry, if a table row is selected.
    pub selected_socket: Option<&'a SocketEntry>,
}

/// Returns cell styling for a socket state, distinguishing UDP `UNCONN` from TCP states.
fn state_style(proto: &str, state: &TcpState) -> Style {
    // Muted cyan distinguishes connectionless UDP sockets from TCP connection states.
    if matches!(proto, "udp" | "udp6") && *state == TcpState::Close {
        return Style::default().fg(Color::Cyan);
    }

    match state {
        TcpState::Established => Style::default().fg(Color::Green),
        TcpState::Listen => Style::default().fg(Color::Yellow),
        TcpState::CloseWait | TcpState::LastAck | TcpState::Closing => {
            Style::default().fg(Color::Red)
        }
        TcpState::TimeWait | TcpState::FinWait1 | TcpState::FinWait2 => {
            Style::default().fg(Color::Magenta)
        }
        _ => Style::default().fg(Color::DarkGray),
    }
}

/// Renders the header summary, scrollable socket table, optional inspector, and keybind footer.
pub fn draw_ui(frame: &mut Frame, snap: &UiSnapshot<'_>, table_state: &mut TableState) {
    // Reserve fixed 3-row header and footer bars with a flexible body in between.
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    render_header(frame, outer[0], snap);

    if snap.show_inspector {
        // Split body vertically when the `[i]` inspector pane is active.
        let body = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(outer[1]);

        render_socket_table(frame, body[0], snap, table_state);
        render_inspector(frame, body[1], snap);
    } else {
        render_socket_table(frame, outer[1], snap, table_state);
    }

    render_footer(frame, outer[2], snap);
}

/// Renders detailed metadata for the currently selected socket in the `[i]` inspector pane.
fn render_inspector(frame: &mut Frame, area: Rect, snap: &UiSnapshot<'_>) {
    let lines = match snap.selected_socket {
        Some(sock) => {
            // Fall back cleanly when an inode is unmapped or belongs to a restricted process.
            let proc_text = match snap.proc_map.get(&sock.inode) {
                Some(info) => format!("{} (PID {})", info.name, info.pid),
                None => "unmapped / permission denied".to_string(),
            };

            // Show both exact raw endpoints and normalized display addresses (such as IPv4-mapped IPv6).
            let local_norm = format_socket_addr(sock.local_addr);
            let remote_norm = format_socket_addr(sock.remote_addr);

            vec![
                Line::from(vec![
                    Span::styled("Proto / State: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!(
                        "{}  |  {}",
                        sock.proto,
                        display_state_for_proto(sock.proto, sock.state)
                    )),
                    Span::styled("    UID: ", Style::default().fg(Color::Yellow)),
                    Span::raw(sock.uid.to_string()),
                    Span::styled("    Inode: ", Style::default().fg(Color::Yellow)),
                    Span::raw(sock.inode.to_string()),
                ]),
                Line::from(vec![
                    Span::styled("Local (exact): ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("{}  (display: {})", sock.local_addr, local_norm)),
                ]),
                Line::from(vec![
                    Span::styled("Remote (exact): ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("{}  (display: {})", sock.remote_addr, remote_norm)),
                ]),
                Line::from(vec![
                    Span::styled("Process: ", Style::default().fg(Color::Yellow)),
                    Span::raw(proc_text),
                ]),
            ]
        }
        None => vec![Line::from("No socket selected.")],
    };

    let inspector = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Socket Details [i]"),
    );
    frame.render_widget(inspector, area);
}

/// Draws the top bar with visible socket count, active filters, cadence, and live/paused badge.
fn render_header(frame: &mut Frame, area: Rect, snap: &UiSnapshot<'_>) {
    // Show a trailing cursor block while typing a search query, or "-" when idle and empty.
    let search_display = if snap.searching {
        format!("{}_", snap.search_query)
    } else if snap.search_query.is_empty() {
        "-".to_string()
    } else {
        snap.search_query.to_string()
    };

    let mut spans = vec![
        Span::styled(
            " socktop ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "| shown: {} | filter: {} | proto: {} | sort: {} | search: {} | interval: {}ms | ",
            snap.sockets.len(),
            snap.filter_label,
            snap.proto_label,
            snap.sort_label,
            search_display,
            snap.interval_ms
        )),
    ];

    if snap.paused {
        spans.push(Span::styled(
            "PAUSED",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::styled("LIVE", Style::default().fg(Color::Green)));
    }

    let line = Line::from(spans);
    let header = Paragraph::new(line).block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(header, area);
}

/// Draws the stateful socket table with selection highlighting and scroll tracking.
fn render_socket_table(
    frame: &mut Frame,
    area: Rect,
    snap: &UiSnapshot<'_>,
    table_state: &mut TableState,
) {
    let header_cells = ["PROTO", "STATE", "LOCAL", "REMOTE", "PID", "PROCESS"]
        .into_iter()
        .map(|h| {
            Cell::from(h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1);

    let rows = snap.sockets.iter().map(|sock| {
        // Sockets held by the kernel (such as TIME-WAIT) or restricted PIDs may have no match.
        let (pid_str, proc_name) = match snap.proc_map.get(&sock.inode) {
            Some(info) => (info.pid.to_string(), info.name.as_str()),
            None => ("-".to_string(), "-"),
        };

        Row::new(vec![
            Cell::from(sock.proto),
            Cell::from(display_state_for_proto(sock.proto, sock.state))
                .style(state_style(sock.proto, &sock.state)),
            Cell::from(format_socket_addr(sock.local_addr)),
            Cell::from(format_socket_addr(sock.remote_addr)),
            Cell::from(pid_str),
            Cell::from(proc_name),
        ])
    });

    let widths = [
        Constraint::Length(7),
        Constraint::Length(13),
        Constraint::Length(22),
        Constraint::Length(22),
        Constraint::Length(9),
        Constraint::Min(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("TCP Sockets"))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    frame.render_stateful_widget(table, area, table_state);
}

/// Draws context-sensitive keybind hints for normal navigation or active search input.
fn render_footer(frame: &mut Frame, area: Rect, snap: &UiSnapshot<'_>) {
    let inspector_state = if snap.show_inspector { "on" } else { "off" };
    let normal_keys = format!(
        " [↑/↓ or j/k] scroll   [/] search   [f] filter   [p] proto   [s] sort   [i] inspect ({inspector_state})   [space] pause   [q / Ctrl+C] quit"
    );

    // Swap in search input controls while typing a query in the header bar.
    let text = if snap.searching {
        " [type] filter query   [Backspace] delete   [Enter] apply   [Esc] clear & cancel"
    } else {
        normal_keys.as_str()
    };

    let footer = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Keys"));
    frame.render_widget(footer, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::{Color, Style};

    #[test]
    fn styles_udp_and_udp6_unconn_distinctly_from_tcp_close() {
        let udp_unconn = state_style("udp", &TcpState::Close);
        let udp6_unconn = state_style("udp6", &TcpState::Close);
        let tcp_close = state_style("tcp", &TcpState::Close);

        assert_eq!(udp_unconn, Style::default().fg(Color::Cyan));
        assert_eq!(udp6_unconn, Style::default().fg(Color::Cyan));
        assert_ne!(udp_unconn, tcp_close);
    }

    #[test]
    fn styles_common_tcp_states_as_expected() {
        assert_eq!(
            state_style("tcp", &TcpState::Established),
            Style::default().fg(Color::Green)
        );
        assert_eq!(
            state_style("tcp6", &TcpState::Listen),
            Style::default().fg(Color::Yellow)
        );
        assert_eq!(
            state_style("tcp", &TcpState::CloseWait),
            Style::default().fg(Color::Red)
        );
        assert_eq!(
            state_style("tcp", &TcpState::TimeWait),
            Style::default().fg(Color::Magenta)
        );
        assert_eq!(
            state_style("udp", &TcpState::Established),
            Style::default().fg(Color::Green)
        );
    }

    #[test]
    fn renders_selected_socket_details_in_inspector() {
        use ratatui::{Terminal, backend::TestBackend};

        // Build a dual-stack IPv4-mapped IPv6 socket fixture with mapped PID metadata.
        let sock = SocketEntry {
            proto: "tcp6",
            local_addr: "[::ffff:192.168.1.42]:8443".parse().unwrap(),
            remote_addr: "[::ffff:10.0.0.15]:51514".parse().unwrap(),
            state: TcpState::Established,
            uid: 1000,
            inode: 98765,
        };

        let mut proc_map = HashMap::new();
        proc_map.insert(
            98765,
            ProcessInfo {
                pid: 4321,
                name: "sshd".to_string(),
            },
        );

        let snap = UiSnapshot {
            sockets: std::slice::from_ref(&sock),
            proc_map: &proc_map,
            interval_ms: 1000,
            paused: false,
            filter_label: "All",
            proto_label: "All",
            sort_label: "None",
            search_query: "",
            searching: false,
            show_inspector: true,
            selected_socket: Some(&sock),
        };

        // Render into a wide-enough in-memory buffer so addresses and labels do not clip.
        let backend = TestBackend::new(120, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                render_inspector(frame, frame.area(), &snap);
            })
            .unwrap();

        // Flatten the terminal grid into lines for substring assertions.
        let buf = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                rendered.push_str(buf[(x, y)].symbol());
            }
            rendered.push('\n');
        }

        assert!(rendered.contains("1000"));
        assert!(rendered.contains("98765"));
        assert!(rendered.contains("[::ffff:192.168.1.42]:8443"));
        assert!(rendered.contains("[::ffff:10.0.0.15]:51514"));
        assert!(rendered.contains("sshd"));
        assert!(rendered.contains("4321"));
    }
}
