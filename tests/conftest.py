"""Shared fixtures."""

from __future__ import annotations

import pytest

from vigil.models import Connection, Process, Snapshot


@pytest.fixture
def suspicious_process() -> Process:
    return Process(
        pid=4242,
        ppid=1,
        name="kworker",
        exe="/tmp/.hidden/kworker",
        cmdline="/tmp/.hidden/kworker --daemon",
        uid=1000,
    )


@pytest.fixture
def legitimate_process() -> Process:
    return Process(
        pid=100,
        ppid=1,
        name="nginx",
        exe="/usr/sbin/nginx",
        cmdline="nginx: worker process",
        uid=33,
    )


@pytest.fixture
def c2_connection() -> Connection:
    return Connection(
        pid=4242,
        local_addr="10.0.0.5",
        local_port=51422,
        remote_addr="203.0.113.7",
        remote_port=443,
        state="ESTABLISHED",
        inode="98765",
    )


@pytest.fixture
def snapshot(suspicious_process, legitimate_process, c2_connection) -> Snapshot:
    return Snapshot(
        processes=[suspicious_process, legitimate_process],
        connections=[c2_connection],
    )
