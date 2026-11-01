"""Collector parsing tests.

These run on any platform: every parser takes injected text rather than reading
/proc itself. The fixtures use real kernel output, including the awkward cases
(comm containing spaces and parentheses, IPv6 padding, malformed lines).
"""

from __future__ import annotations

import pytest

from vigil.collector import (
    hex_to_ip,
    parse_proc_net_tcp,
    parse_stat,
    read_cmdline,
)


class TestHexToIp:
    def test_loopback_is_decoded_little_endian(self):
        """0100007F is 127.0.0.1, not 1.0.0.127.

        Getting this backwards mislabels every connection in the tool while
        still producing plausible-looking output, so it is tested explicitly.
        """
        assert hex_to_ip("0100007F") == "127.0.0.1"

    def test_zero_address(self):
        assert hex_to_ip("00000000") == "0.0.0.0"

    def test_typical_lan_address(self):
        # 10.0.0.5 little-endian is 0500000A
        assert hex_to_ip("0500000A") == "10.0.0.5"

    def test_ipv6_full_length(self):
        # ::1 written as four little-endian words
        assert hex_to_ip("00000000000000000000000001000000") == "::1"

    def test_malformed_returns_empty(self):
        assert hex_to_ip("XYZ") == ""
        assert hex_to_ip("") == ""


class TestParseProcNetTcp:
    def test_parses_a_real_established_row(self):
        text = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0500000A:C9DE 070000CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 98765 1 0 20 4 30 10 -1\n"
        )
        conns = parse_proc_net_tcp(text)
        assert len(conns) == 1
        conn = conns[0]
        assert conn.local_addr == "10.0.0.5"
        assert conn.local_port == 51678  # 0xC9DE
        assert conn.remote_addr == "203.0.0.7"  # 070000CB
        assert conn.remote_port == 443
        assert conn.state == "ESTABLISHED"
        assert conn.inode == "98765"

    def test_listen_state_decoded(self):
        text = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0 20 4 30 10 -1\n"
        )
        conn = parse_proc_net_tcp(text)[0]
        assert conn.state == "LISTEN"
        assert conn.local_port == 8080

    def test_header_only_yields_nothing(self):
        text = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        )
        assert parse_proc_net_tcp(text) == []

    def test_malformed_row_skipped_not_raised(self):
        """One odd line must not stop the collector defending the host."""
        text = (
            "  sl  local_address rem_address   st ...\n"
            "garbage\n"
            "   0: nothex:ZZZZ 070000CB:01BB 01 0 0 0 0 0 0\n"
        )
        assert parse_proc_net_tcp(text) == []

    def test_unknown_state_code_passes_through(self):
        text = (
            "  sl  local_address rem_address   st ...\n"
            "   0: 0500000A:C9DE 070000CB:01BB FF 0 0 0 0 0 0 999\n"
        )
        conn = parse_proc_net_tcp(text)[0]
        assert conn.state == "FF"


class TestParseStat:
    def test_normal_process(self):
        stat = "1234 (nginx) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 2 0 0 20 0 1 0 98765 123456 789 18446744073709551615"
        proc = parse_stat(1234, stat)
        assert proc is not None
        assert proc.pid == 1234
        assert proc.name == "nginx"
        assert proc.ppid == 1

    def test_comm_containing_space_and_parens(self):
        """The classic /proc/pid/stat bug: comm may contain ')' characters.

        Splitting on the first ')' gives the wrong name and shifts every
        subsequent field. The parser must split on the last ')'.
        """
        stat = "999 (evil) proc) S 1 999 999 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 111 2 3 4"
        proc = parse_stat(999, stat)
        assert proc is not None
        assert proc.name == "evil) proc"
        assert proc.ppid == 1

    def test_truncated_stat_returns_none(self):
        assert parse_stat(1, "1234 (x) S") is None

    def test_empty_text_returns_none(self):
        assert parse_stat(1, "") is None

    def test_start_time_parsed(self):
        # Fields after comm start at stat field 3 (state). starttime is field
        # 22, so it sits at index 19 of this list -- 19 filler values, then it.
        fields = ["S", "1", "1234", "1234", "0", "-1", "0", "0", "0", "0",
                  "0", "0", "0", "0", "0", "0", "0", "0", "0", "4242"]
        stat = f"1234 (x) {' '.join(fields)}"
        proc = parse_stat(1234, stat)
        assert proc is not None
        assert proc.start_time == 4242.0


class TestReadCmdline:
    def test_nul_separated_joined_with_spaces(self):
        assert read_cmdline("/usr/bin/python\0script.py\0--flag\0") == (
            "/usr/bin/python script.py --flag"
        )

    def test_empty_cmdline(self):
        """Kernel threads have an empty cmdline; that is normal."""
        assert read_cmdline("") == ""

    def test_trailing_nuls_dropped(self):
        assert read_cmdline("a\0\0\0") == "a"
