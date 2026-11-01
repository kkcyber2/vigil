class TestSummary:
    def test_counts_executed_planned_and_refused(self, fixed_clock):
        """The three buckets are mutually exclusive.

        This test previously asserted planned_only=2 and refused=1 across two
        non-executed entries -- arithmetically impossible, and it locked in a
        real bug: a dry-run entry was tallied as both. A summary whose buckets
        overlap cannot be used to answer "how many actions did the policy
        actually stop?".
        """
        log = AuditLog(clock=fixed_clock)
        log.record("process", "pid:1", "r", "high", "kill", True)
        log.record("process", "pid:2", "r", "high", "kill", False, "refused: dry_run")
        log.record("process", "pid:3", "r", "high", "kill", False, "refused: pid 1 protected")
        summary = log.summary()

        assert summary["entries"] == 3
        assert summary["executed"] == 1
        assert summary["planned_only"] == 1
        assert summary["refused"] == 1
        assert summary["chain_valid"] is True

    def test_buckets_sum_to_entry_count(self, fixed_clock):
        """Every entry lands in exactly one bucket. Asserted as an invariant."""
        log = AuditLog(clock=fixed_clock)
        log.record("process", "a", "r", "low", "alert", True)
        log.record("process", "b", "r", "low", "alert", False, "refused: dry_run enabled")
        log.record("process", "c", "r", "low", "kill", False, "refused: uid 0")
        log.record("process", "d", "r", "low", "kill", False, "below min_severity high")
        s = log.summary()
        assert s["executed"] + s["planned_only"] + s["refused"] == s["entries"]

    def test_dry_run_is_not_counted_as_a_refusal(self, fixed_clock):
        """A dry run is the whole mode of the tool; it is not the policy saying no."""
        log = AuditLog(clock=fixed_clock)
        log.record("process", "a", "r", "high", "kill", False, "refused: dry_run enabled")
        s = log.summary()
        assert s["planned_only"] == 1
        assert s["refused"] == 0
