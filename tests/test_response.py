"""Policy gate tests.

These are the tests that matter most. Every other part of the system can be
wrong and the worst outcome is a missed detection or a false alarm. If this gate
is wrong, the tool kills the wrong process.
"""

from __future__ import annotations

import pytest

from vigil.models import Connection, Process
from vigil.response import Decision, ResponsePolicy, _in_network


def make_process(pid=4242, uid=1000, exe="/tmp/bad"):
    return Process(pid=pid, name="bad", exe=exe, uid=uid)


class TestDryRunDefault:
    def test_policy_defaults_to_dry_run(self):
        """Constructing a policy with no arguments must not permit action."""
        policy = ResponsePolicy()
        result = policy.evaluate("alert", "r1", process=make_process())
        assert result.decision is Decision.DRY_RUN
        assert not result.may_execute

    def test_dry_run_blocks_everything_even_at_max_ceiling(self):
        policy = ResponsePolicy(dry_run=True, max_action="kill")
        for action in ("alert", "block", "quarantine", "kill"):
            result = policy.evaluate(action, "r1", process=make_process())
            assert result.decision is Decision.DRY_RUN


class TestActionCeiling:
    def test_default_ceiling_allows_only_alert(self):
        policy = ResponsePolicy(dry_run=False)
        assert policy.evaluate("alert", "r").may_execute
        for action in ("block", "quarantine", "kill"):
            assert not policy.evaluate(action, "r").may_execute

    def test_raising_ceiling_permits_that_action(self):
        policy = ResponsePolicy(dry_run=False, max_action="kill")
        result = policy.evaluate("kill", "r", process=make_process())
        assert result.decision is Decision.ALLOW

    def test_unknown_action_refused(self):
        policy = ResponsePolicy(dry_run=False, max_action="kill")
        result = policy.evaluate("rm-rf", "r")
        assert result.decision is Decision.REFUSE
        assert "unknown action" in result.reason

    def test_refusal_reason_names_the_ceiling(self):
        policy = ResponsePolicy(dry_run=False, max_action="alert")
        result = policy.evaluate("kill", "r", process=make_process())
        assert "max_action='alert'" in result.reason


class TestProtectedProcesses:
    def test_pid_1_is_refused_outright(self):
        """Killing init takes the machine down. This is not a dry-run nicety."""
        policy = ResponsePolicy(dry_run=False, max_action="kill")
        result = policy.evaluate("kill", "r", process=make_process(pid=1))
        assert result.decision is Decision.REFUSE
        assert "protected" in result.reason

    def test_pid_0_is_refused(self):
        policy = ResponsePolicy(dry_run=False, max_action="kill")
        assert policy.evaluate("kill", "r", process=make_process(pid=0)).decision is Decision.REFUSE

    def test_root_owned_process_refused_outright(self):
        """Root-owned processes are refused, not merely downgraded.

        Downgrading to a dry run would still be safe, but REFUSE is the honest
        answer: the policy has no intention of ever acting on this process.
        """
        policy = ResponsePolicy(dry_run=False, max_action="kill")
        result = policy.evaluate("kill", "r", process=make_process(uid=0))
        assert result.decision is Decision.REFUSE
        assert "uid 0" in result.reason

    def test_system_path_downgraded_to_dry_run(self):
        policy = ResponsePolicy(dry_run=False, max_action="kill")
        result = policy.evaluate(
            "kill", "r", process=make_process(exe="/usr/sbin/nginx")
        )
        assert result.decision is Decision.DRY_RUN
        assert "system path" in result.reason

    def test_user_writable_path_is_allowed_when_ceiling_permits(self):
        policy = ResponsePolicy(dry_run=False, max_action="kill")
        result = policy.evaluate("kill", "r", process=make_process(exe="/home/u/x"))
        assert result.decision is Decision.ALLOW


class TestNeverActRules:
    def test_listed_rule_cannot_act(self):
        policy = ResponsePolicy(
            dry_run=False, max_action="kill", never_act_rules={"noisy-rule"}
        )
        result = policy.evaluate("kill", "noisy-rule", process=make_process())
        assert result.decision is Decision.DRY_RUN
        assert "never_act_rules" in result.reason

    def test_unlisted_rule_still_acts(self):
        policy = ResponsePolicy(
            dry_run=False, max_action="kill", never_act_rules={"other"}
        )
        assert policy.evaluate("kill", "mine", process=make_process()).may_execute


class TestNetworkScope:
    def test_allowed_networks_permits_inside_range(self):
        policy = ResponsePolicy(
            dry_run=False, max_action="block", allowed_networks=["10.0.0.0/8"]
        )
        conn = Connection(pid=1, local_addr="1.1.1.1", local_port=1,
                          remote_addr="10.5.5.5", remote_port=443)
        assert policy.evaluate("block", "r", connection=conn).may_execute

    def test_allowed_networks_refuses_outside_range(self):
        policy = ResponsePolicy(
            dry_run=False, max_action="block", allowed_networks=["10.0.0.0/8"]
        )
        conn = Connection(pid=1, local_addr="1.1.1.1", local_port=1,
                          remote_addr="203.0.113.9", remote_port=443)
        result = policy.evaluate("block", "r", connection=conn)
        assert result.decision is Decision.DRY_RUN
        assert "outside allowed_networks" in result.reason

    def test_malformed_address_does_not_raise(self):
        """A hostname must not make the policy check explode — that fails open."""
        assert _in_network("example.com", "10.0.0.0/8") is False
        assert _in_network("", "10.0.0.0/8") is False


class TestReasonQuality:
    def test_every_result_has_a_non_empty_reason(self):
        """An unexplained refusal is indistinguishable from a bug."""
        policy = ResponsePolicy()
        assert policy.evaluate("alert", "r").reason
        policy2 = ResponsePolicy(dry_run=False, max_action="kill")
        assert policy2.evaluate("kill", "r", process=make_process(pid=1)).reason
        assert policy2.evaluate("nonsense", "r").reason
