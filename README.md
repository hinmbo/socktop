# socktop

A terminal-based network socket monitor for Linux built in Rust with `ratatui` and `crossterm`. `socktop` reads `/proc/net/{tcp,tcp6,udp,udp6}` and maps socket inodes to owning processes via `/proc/<pid>/fd`, offering both a one-shot stdout snapshot (`--once`) and an interactive terminal UI.

<img width="1920" height="1163" alt="socktop-preview" src="https://github.com/user-attachments/assets/60dc049a-66aa-4819-93d4-74a50ebcef0b" />

## Features

* **Protocol & State Coverage:** Monitors `tcp`, `tcp6`, `udp`, and `udp6` sockets, decoding little-endian hex addresses/ports and formatting unconnected UDP sockets as `UNCONN`.
* **Live Filtering, Search & Sorting:** Cycle state filters (`f`), filter by protocol (`p`), search interactively (`/`) across process names, PIDs, IP addresses, exact ports, protocol, and state, and sort (`s`) by local port, remote port, or PID.
* **Socket Inspector (`[i]`):** Toggle a detail pane for the selected row showing protocol, state, `UID`, `inode`, raw and normalized local/remote endpoints (unwrapping IPv4-mapped IPv6 `::ffff:x.x.x.x` addresses), and mapped process metadata.
* **Pause & Snapshot Modes:** Pause live polling (`Space`) to inspect a static view, set custom refresh intervals (`--interval-ms <ms>`), or print a single plain-text table and exit (`--once`).
* **Testability:** Pure UI snapshot rendering (`UiSnapshot`) and `ratatui::backend::TestBackend` tests verify layouts and inspector output without requiring a live terminal.

## Architecture

`socktop` is organized into four focused modules:

* **`src/main.rs`:** Parses CLI flags (`--once`, `--interval-ms`, `--help`), manages filter/sort/search/selection state, runs the `crossterm` event loop with safe terminal restoration, and implements `--once` stdout formatting.
* **`src/net_sockets.rs`:** Parses `/proc/net/{tcp,tcp6,udp,udp6}`, decodes IPv4 and IPv6 hex endpoints and `TcpState` codes, normalizes IPv4-mapped IPv6 display addresses, and skips malformed or transient lines.
* **`src/proc_map.rs`:** Walks `/proc/<pid>/fd` to parse `socket:[<inode>]` symlinks and reads `/proc/<pid>/comm`, building an inode-to-`ProcessInfo` (`pid`, `name`) lookup map while tolerating exiting or restricted processes.
* **`src/ui.rs`:** Renders the status header, scrollable socket table, optional `[i]` socket inspector pane, and context-sensitive footer using `ratatui`.

## Installation & Usage

### Build and Run

```bash
# Build release binary
cargo build --release

# Run interactive TUI with default 1000 ms refresh interval
cargo run

# Run interactive TUI with a 500 ms refresh interval
cargo run -- --interval-ms 500

# Print a single socket snapshot to stdout and exit
cargo run -- --once

```

### Format, Lint & Test

```bash
cargo fmt && cargo clippy && cargo test

```

## Keybindings

| Key | Mode | Action |
| --- | --- | --- |
| `↑` / `↓` or `j` / `k` | Normal | Move row selection up or down |
| `/` | Normal | Enter live search mode |
| `f` | Normal | Cycle socket state filter (adapted to active protocol filter) |
| `p` | Normal | Cycle protocol filter (`ALL` -> `TCP` -> `UDP`) |
| `s` | Normal | Cycle sort mode (`DEFAULT` -> `LOCAL-PORT` -> `REMOTE-PORT` -> `PID`) |
| `i` | Normal | Toggle the socket details inspector pane |
| `Space` | Normal | Pause or resume `/proc` polling |
| `Esc` | Normal | Clear active search query (when non-empty) |
| `q` or `Ctrl+C` | Normal | Quit `socktop` and restore terminal state |
| Type / `Backspace` | Search | Edit search query and update matching rows live |
| `Enter` | Search | Keep search query and return to normal navigation |
| `Esc` | Search | Clear search query and exit search mode |

## Permissions & Platform Notes

* **Linux `/proc` Requirement:** `socktop` relies on Linux's `/proc/net/*` and `/proc/<pid>/fd` pseudo-filesystems and is intended for Linux systems.
* **Unmapped Sockets & Process Visibility:** Sockets without an active owning process (such as `TIME-WAIT` sockets) or sockets belonging to processes owned by other users may show `-` in the table and `unmapped / permission denied` in the inspector unless `socktop` runs with sufficient privileges (for example via `sudo` or appropriate capabilities).
