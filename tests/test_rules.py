"""Rule engine tests.

The bulk of these exist because a detector that silently never fires is worse
than no detector: it produces false confidence. Several tests here assert that
a *wrong* rule fails loudly at load time rather than going quiet at runtime.
"""

from __future__ import annotations

import pytest

from vigil.models import Snapshot
from vigil.rules import (
    Condition,
    MatchMode,
    Rule,
    RuleSet,
    Severity,
    default_rules,
)


class TestCondition:
    def test_exact_match(self):
        c = Condition("name", MatchMode.EXACT, "kworker")
        assert c.evaluate({"name": "kworker"})
        assert not c.evaluate({"name": "KWorker"})

    def test_missing_field_never_matches(self):
        c = Condition("name", MatchMode.EXACT, "kworker")
        assert not c.evaluate({})

    def test_missing_field_does_not_satisfy_exact_none(self):
        """A field absent must not equal an expected None.

        Without this, a rule written to catch "exe is null" would fire on every
        context that simply does not carry an exe key.
        """
        c = Condition("name", MatchMode.EXACT, None)
        assert not c.evaluate({})

    def test_contains_is_case_insensitive(self):
        c = Condition("cmdline", MatchMode.CONTAINS, "DELETED")
        assert c.evaluate({"cmdline": "foo-bar (deleted)"})

    def test_contains_any(self):
        c = Condition("exe", MatchMode.CONTAINS_ANY, ["/tmp/", "/dev/shm/"])
        assert c.evaluate({"exe": "/dev/shm/x"})
        assert not c.evaluate({"exe": "/usr/bin/x"})

    def test_in_list(self):
        c = Condition("name", MatchMode.IN, ["sh", "bash"])
        assert c.evaluate({"name": "bash"})
        assert not c.evaluate({"name": "zsh"})

    def test_in_list_on_unhashable_value_does_not_raise(self):
        """A dict value against an IN condition must be a non-match, not a crash."""
        c = Condition("process", MatchMode.IN, ["a"])
        assert not c.evaluate({"process": {"nested": True}})

    def test_regex(self):
        c = Condition("remote_addr", MatchMode.REGEX, r"^\d+\.\d+\.\d+\.\d+$")
        assert c.evaluate({"remote_addr": "1.2.3.4"})
        assert not c.evaluate({"remote_addr": "example.com"})

    def test_exists_true_and_false(self):
        present = Condition("exe", MatchMode.EXISTS, True)
        absent = Condition("exe", MatchMode.EXISTS, False)
        assert present.evaluate({"exe": "/bin/x"})
        assert not present.evaluate({})
        assert absent.evaluate({})
        assert not absent.evaluate({"exe": "/bin/x"})

    def test_invalid_regex_fails_at_construction(self):
        """Compiling eagerly turns a silent runtime miss into a load error."""
        with pytest.raises(ValueError, match="invalid regex"):
            Condition("exe", MatchMode.REGEX, "([unclosed")

    def test_dotted_path(self):
        c = Condition("process.exe", MatchMode.CONTAINS, "/tmp/")
        ctx = {"process": {"exe": "/tmp/bad"}}
        assert c.evaluate(ctx)

    def test_dotted_path_into_empty_process(self):
        """An unattributed connection carries process={}. Must not raise."""
        c = Condition("process.exe", MatchMode.CONTAINS, "/tmp/")
        assert not c.evaluate({"process": {}})


class TestRuleValidation:
    def test_rule_without_conditions_rejected(self):
        with pytest.raises(ValueError, match="no conditions"):
            Rule(id="x", title="X", severity=Severity.LOW, conditions=())

    def test_invalid_scope_rejected(self):
        with pytest.raises(ValueError, match="invalid scope"):
            Rule(
                id="x",
                title="X",
                severity=Severity.LOW,
                scope="filesystem",
                conditions=(Condition("a", MatchMode.EXACT, 1),),
            )

    def test_from_dict_missing_key_names_the_key(self):
        with pytest.raises(ValueError, match="missing required key 'title'"):
            Rule.from_dict({"id": "x", "severity": "low"})

    def test_from_dict_unknown_severity_lists_valid_ones(self):
        with pytest.raises(ValueError, match="unknown severity"):
            Rule.from_dict(
                {"id": "x", "title": "X", "severity": "apocalyptic", "conditions": []}
            )

    def test_from_dict_roundtrip(self):
        rule = Rule.from_dict(
            {
                "id": "r1",
                "title": "T",
                "severity": "high",
                "scope": "process",
                "action": "kill",
                "conditions": [{"field": "name", "mode": "exact", "value": "bad"}],
            }
        )
        assert rule.id == "r1"
        assert rule.severity is Severity.HIGH
        assert rule.action == "kill"
        assert rule.matches({"kind": "process", "name": "bad"})
        assert not rule.matches({"kind": "connection", "name": "bad"})


class TestRuleSet:
    def test_duplicate_id_rejected(self):
        rs = RuleSet()
        rule = Rule(
            id="dup",
            title="T",
            severity=Severity.LOW,
            conditions=(Condition("name", MatchMode.EXACT, "x"),),
        )
        rs.add(rule)
        with pytest.raises(ValueError, match="duplicate rule id"):
            rs.add(rule)

    def test_warning_for_process_rule_reading_only_connection_fields(self):
        rs = RuleSet()
        rs.add(
            Rule(
                id="misfiled",
                title="T",
                severity=Severity.LOW,
                scope="process",
                conditions=(Condition("connection.remote_port", MatchMode.EXACT, 4444),),
            )
        )
        warnings = rs.warnings()
        assert len(warnings) == 1
        assert "can never fire" in warnings[0]

    def test_warning_for_connection_rule_reading_only_process_fields(self):
        rs = RuleSet()
        rs.add(
            Rule(
                id="misfiled2",
                title="T",
                severity=Severity.LOW,
                scope="connection",
                conditions=(Condition("process.name", MatchMode.EXACT, "x"),),
            )
        )
        assert any("never match" in w for w in rs.warnings())

    def test_no_warning_for_mixed_conditions(self):
        rs = RuleSet()
        rs.add(
            Rule(
                id="ok",
                title="T",
                severity=Severity.LOW,
                scope="connection",
                conditions=(
                    Condition("process.exe", MatchMode.CONTAINS, "/tmp/"),
                    Condition("state", MatchMode.EXACT, "ESTABLISHED"),
                ),
            )
        )
        assert rs.warnings() == []


class TestDefaultRules:
    def test_default_pack_loads_and_has_no_authoring_warnings(self):
        """The shipped pack must not contain a rule that can never fire."""
        rules = default_rules()
        assert len(rules) >= 6
        assert rules.warnings() == []

    def test_all_ids_unique(self):
        ids = [r.id for r in default_rules()]
        assert len(ids) == len(set(ids))

    def test_tmp_executable_fires(self, suspicious_process):
        rules = default_rules()
        ctx = Snapshot().context_for_process(suspicious_process)
        matched = [r.id for r in rules if r.matches(ctx)]
        assert "proc-tmp-exec" in matched

    def test_legitimate_nginx_does_not_fire(self, legitimate_process):
        """A baseline pack that flags nginx is unusable in production."""
        rules = default_rules()
        ctx = Snapshot().context_for_process(legitimate_process)
        matched = [r.id for r in rules if r.matches(ctx)]
        assert matched == []

    def test_deleted_binary_rule(self):
        from vigil.models import Process

        proc = Process(pid=7, name="x", exe="/tmp/x (deleted)", uid=1000)
        ctx = Snapshot().context_for_process(proc)
        matched = [r.id for r in default_rules() if r.matches(ctx)]
        assert "proc-deleted-binary" in matched

    def test_crypto_miner_rule_requests_quarantine(self):
        rules = default_rules()
        rule = rules.get("proc-crypto-miner-name")
        assert rule is not None
        assert rule.action == "quarantine"
