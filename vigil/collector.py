"""Host collectors.

Linux only. Reads /proc directly rather than shelling out to ps/netstat: the
format is stable, there is no parsing of human-oriented column output, and the
collector cannot be fooled by a PATH-shadowed binary.

Every parser here is written against real /proc content and takes injected text
so the parsing can be tested on any platform, including CI on macOS.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import replace
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import Connection, Process, Snapshot


# TCP state codes as they appear in /proc/net/tcp. Only the ones worth
# surfacing are named; everything else is passed through as a hex code.
_TCP_STATES: Dict[str, str] = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def hex_to_ip(hex_addr: str) -> str:
    """Decode a /proc/net/tcp address.

    The kernel prints IPv4 addresses as a little-endian 32-bit hex word, so
    "0100007F" is 127.0.0.1 and not 1.0.0.127. Getting this backwards silently
    mislabels every connection, so it is decoded through struct rather than
    string surgery.
    """
    if len(hex_addr) == 8:
        packed = struct.pack("<L", int(hex_addr, 16))
        return socket.inet_ntoa(packed)
    if len(hex_addr) == 32:
        # IPv6 is four little-endian 32-bit words.
        raw = b"".join(
            struct.pack("<L", int(hex_addr[i : i + 8], 16))
            for i in range(0, 32, 8)
        )
        return socket.inet_ntop(socket.AF_INET6, raw)
    return ""


def parse_proc_net_tcp(text: str, protocol: str = "tcp") -> List[Connection]:
    """Parse /proc/net/tcp or /proc/net/tcp6.

    Each data line is: sl, local_address, rem_address, st, tx_queue:rx_queue,
    tr:tm->when, retrnsmt, uid, timeout, inode. Only the fields this tool needs
    are read, and malformed lines are skipped rather than raising: a collector
    that dies on one odd line stops defending entirely.
    """
    out: List[Connection] = []
    lines = text.splitlines()
    for line in lines[1:]:  # first line is the header
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            local_addr_hex, local_port_hex = parts[1].split(":")
            remote_addr_hex, remote_port_hex = parts[2].split(":")
            state = _TCP_STATES.get(parts[3].upper(), parts[3].upper())
            inode = parts[9]
            local_addr = hex_to_ip(local_addr_hex)
            remote_addr = hex_to_ip(remote_addr_hex)
            local_port = int(local_port_hex, 16)
            remote_port = int(remote_port_hex, 16)
        except (ValueError, IndexError):
            continue

        # hex_to_ip returns "" for an undecodable address rather than raising.
        # Emitting a connection with an empty address would produce a finding
        # whose subject reads "conn:tcp::443" -- unactionable and confusing --
        # so the row is dropped instead.
        if len(local_addr_hex) not in (8, 32) or len(remote_addr_hex) not in (8, 32):
            continue
        if not local_addr or not remote_addr:
            continue

        out.append(
            Connection(
                pid=0,  # filled in by the socket-inode join
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                state=state,
                protocol=protocol,
                inode=inode,
            )
        )
    return out


def parse_stat(pid: int, text: str) -> Optional[Process]:
    """Parse /proc/<pid>/stat.

    The comm field is wrapped in parentheses and may itself contain spaces and
    parentheses, so the parse must split on the LAST ')' rather than on
    whitespace. This is the single most common bug in amateur /proc parsers.
    """
    try:
        rparen = text.rindex(")")
        lparen = text.index("(")
    except ValueError:
        return None

    name = text[lparen + 1 : rparen]
    rest = text[rparen + 2 :].split()
    # After comm, field 3 is state, so rest[0] is state and rest[1] is ppid.
    try:
        ppid = int(rest[1])
        start_time = float(rest[19])
    except (IndexError, ValueError):
        return None

    return Process(pid=pid, ppid=ppid, name=name, start_time=start_time)


def read_cmdline(text: str) -> str:
    """NUL-separated argv becomes a single space-joined string."""
    return " ".join(part for part in text.split("\0") if part)


def read_link(path: str) -> str:
    try:
        return os.readlink(path)
    except (OSError, ValueError):
        return ""


class LinuxCollector:
    """Reads a snapshot of the host from /proc."""

    def __init__(self, proc_root: str = "/proc") -> None:
        self.proc_root = Path(proc_root)
        self.available = self.proc_root.is_dir()

    # -- processes ---------------------------------------------------------

    def processes(self) -> List[Process]:
        if not self.available:
            return []
        out: List[Process] = []
        for entry in self.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            proc = self._one_process(pid, entry)
            if proc is not None:
                out.append(proc)
        return out

    def _one_process(self, pid: int, entry: Path) -> Optional[Process]:
        try:
            stat_text = (entry / "stat").read_text(errors="replace")
        except OSError:
            return None  # process exited mid-scan; normal and expected
        base = parse_stat(pid, stat_text)
        if base is None:
            return None

        try:
            cmdline_text = (entry / "cmdline").read_text(errors="replace")
        except OSError:
            cmdline_text = ""

        exe = read_link(str(entry / "exe"))
        try:
            uid = entry.stat().st_uid
        except OSError:
            uid = 0

        return Process(
            pid=pid,
            ppid=base.ppid,
            name=base.name,
            exe=exe,
            cmdline=read_cmdline(cmdline_text),
            uid=uid,
            start_time=base.start_time,
        )

    # -- sockets -----------------------------------------------------------

    def socket_inode_to_pid(self) -> Dict[str, int]:
        """Map socket inode -> owning pid.

        This is the join that makes a connection attributable. It walks every
        fd directory, so it is the expensive part of a scan.
        """
        mapping: Dict[str, int] = {}
        if not self.available:
            return mapping
        for entry in self.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            fd_dir = entry / "fd"
            try:
                fds: Iterable[str] = list(os.listdir(fd_dir))
            except OSError:
                continue  # permission denied on another user's process
            for fd in fds:
                target = read_link(str(fd_dir / fd))
                if target.startswith("socket:["):
                    inode = target[8:-1]
                    mapping[inode] = pid
        return mapping

    def connections(self) -> List[Connection]:
        inode_map = self.socket_inode_to_pid()
        out: List[Connection] = []
        for name, proto in (("tcp", "tcp"), ("tcp6", "tcp6")):
            path = self.proc_root / "net" / name
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for conn in parse_proc_net_tcp(text, proto):
                # Connection is frozen, so the pid join produces a new object.
                # A socket with no owning pid stays pid 0 and is reported as
                # unattributed rather than being dropped: an orphan socket is
                # frequently the interesting one.
                owner = inode_map.get(conn.inode or "", 0)
                out.append(replace(conn, pid=owner))
        return out

    def snapshot(self) -> Snapshot:
        return Snapshot(processes=self.processes(), connections=self.connections())
