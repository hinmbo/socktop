//! Maps Linux socket inodes from `/proc/<pid>/fd` back to their owning process ID and name.
//!
//! Kernel socket tables such as `/proc/net/tcp` list numeric socket inodes rather than PIDs.
//! This module scans `/proc` to connect those inodes to running processes so `socktop` can show
//! which program owns each connection.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// Process details resolved for a socket inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Linux process ID (`PID`) that holds an open file descriptor to the socket.
    pub pid: u32,
    /// Short command name read from `/proc/<pid>/comm`.
    pub name: String,
}

/// Parses a symlink target like `"socket:[48291]"` and returns the inode number `48291`.
///
/// Returns `None` if the target is not a socket symlink (for example a pipe or regular file)
/// or if the value inside brackets is not a valid `u64`.
fn parse_socket_inode_link(target: &str) -> Option<u64> {
    // Extract the substring between `"socket:["` and the trailing `']'`.
    let inner = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

/// Reads `/proc/<pid>/comm` and returns the trimmed process name.
///
/// Falls back to `"<unknown>"` when the file cannot be read or is empty.
fn read_process_name(pid_dir: &Path) -> String {
    match fs::read_to_string(pid_dir.join("comm")) {
        Ok(comm) => {
            // Strip trailing newline/whitespace emitted by the kernel `comm` pseudo-file.
            let trimmed = comm.trim();
            if trimmed.is_empty() {
                "<unknown>".to_string()
            } else {
                trimmed.to_string()
            }
        }
        // Unreadable or vanished `comm` files fall back rather than failing the scan.
        Err(_) => "<unknown>".to_string(),
    }
}

/// Builds a lookup map from socket inode to [`ProcessInfo`] by walking `proc_root`.
///
/// Passing `proc_root` explicitly lets tests point this function at a temporary mock directory
/// instead of the live `/proc` filesystem. Entries for processes that exit mid-scan or belong
/// to restricted users are skipped rather than aborting the scan.
pub fn build_inode_map_from_proc(proc_root: &Path) -> io::Result<HashMap<u64, ProcessInfo>> {
    let mut map = HashMap::new();

    for entry in fs::read_dir(proc_root)? {
        // Ignore transient directory entry errors while walking `/proc`.
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            continue;
        };

        // Skip non-PID entries under `/proc` (such as `net`, `sys`, or `self`).
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        let pid_path = entry.path();
        let fd_dir = pid_path.join("fd");

        // Skip processes whose `fd` directory is restricted or disappears mid-iteration.
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        // Read `comm` lazily only if this process owns at least one socket descriptor.
        let mut proc_name: Option<String> = None;

        for fd_entry in fds.flatten() {
            // Skip broken/vanished fd symlinks or non-UTF8 targets.
            let Ok(link_target) = fs::read_link(fd_entry.path()) else {
                continue;
            };
            let Some(link_str) = link_target.to_str() else {
                continue;
            };
            let Some(inode) = parse_socket_inode_link(link_str) else {
                continue;
            };

            // Cache `comm` across multiple open sockets belonging to the same PID.
            let name = proc_name
                .get_or_insert_with(|| read_process_name(&pid_path))
                .clone();

            // Keep the first resolved owner when multiple descriptors reference the same inode.
            map.entry(inode).or_insert(ProcessInfo { pid, name });
        }
    }

    Ok(map)
}

/// Scans the live `/proc` filesystem and returns a map of socket inodes to [`ProcessInfo`].
pub fn build_inode_map() -> io::Result<HashMap<u64, ProcessInfo>> {
    // Delegate to `build_inode_map_from_proc` so live scans and mock tests share one path.
    build_inode_map_from_proc(Path::new("/proc"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Build an isolated temp directory per test to avoid collisions across parallel test runs.
    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("socktop_{label}_{}_{}", std::process::id(), nanos));
        fs::create_dir_all(&dir).expect("failed to create temp test directory");
        dir
    }

    #[test]
    fn parses_socket_symlink_format() {
        assert_eq!(parse_socket_inode_link("socket:[48291]"), Some(48291));
        assert_eq!(parse_socket_inode_link("pipe:[1234]"), None);
        assert_eq!(parse_socket_inode_link("socket:[notanumber]"), None);
        assert_eq!(parse_socket_inode_link("socket:[48291"), None);
    }

    #[test]
    fn maps_socket_inodes_to_pid_and_comm() {
        let root = unique_temp_dir("proc_map");
        let pid_dir = root.join("4242");
        let fd_dir = pid_dir.join("fd");
        fs::create_dir_all(&fd_dir).expect("failed to create mock fd dir");
        fs::write(pid_dir.join("comm"), "sshd\n").expect("failed to write mock comm");

        // Create one socket symlink and one non-socket pipe symlink to verify filtering.
        symlink("socket:[99101]", fd_dir.join("3")).expect("failed to create socket symlink");
        symlink("pipe:[777]", fd_dir.join("4")).expect("failed to create pipe symlink");

        // Add a non-numeric directory to verify non-PID `/proc` entries are ignored.
        let non_proc = root.join("net");
        fs::create_dir_all(&non_proc).expect("failed to create non-numeric dir");

        let map = build_inode_map_from_proc(&root).expect("failed to build inode map");

        assert_eq!(
            map.get(&99101),
            Some(&ProcessInfo {
                pid: 4242,
                name: "sshd".to_string()
            })
        );
        assert_eq!(map.get(&777), None);
        assert_eq!(map.len(), 1);

        // Best-effort cleanup of temporary test fixtures.
        let _ = fs::remove_dir_all(&root);
    }
}
