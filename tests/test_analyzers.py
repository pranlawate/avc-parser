import unittest
from analyzers.findings import Finding, Findings, FindingSeverity, FindingCategory


class TestFindingDataModel(unittest.TestCase):
    def test_create_finding(self):
        f = Finding(
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.LABELING,
            title="Widespread unlabeled_t files",
            description="50 denial groups target unlabeled_t",
            affected_groups=[0, 1, 5, 12],
            investigation_hints=["Run: fixfiles -v check"],
            evidence={"unlabeled_count": 50},
        )
        self.assertEqual(f.severity, FindingSeverity.CRITICAL)
        self.assertEqual(len(f.affected_groups), 4)

    def test_findings_collection(self):
        f1 = Finding(
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.LABELING,
            title="Test",
            description="Test",
            affected_groups=[0, 1],
        )
        f2 = Finding(
            severity=FindingSeverity.WARNING,
            category=FindingCategory.SYSTEMIC,
            title="Test2",
            description="Test2",
            affected_groups=[1, 2],
        )
        findings = Findings()
        findings.add(f1)
        findings.add(f2)
        self.assertEqual(len(findings.items), 2)
        self.assertEqual(findings.items[0].severity, FindingSeverity.CRITICAL)
        self.assertIn(f1, findings.tags[0])
        self.assertIn(f1, findings.tags[1])
        self.assertIn(f2, findings.tags[1])
        self.assertIn(f2, findings.tags[2])

    def test_findings_remediation_counts(self):
        labeling = Finding(
            severity=FindingSeverity.WARNING,
            category=FindingCategory.LABELING,
            title="Labeling",
            description="",
            affected_groups=[0, 1, 2],
        )
        relabeling = Finding(
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.RELABELING,
            title="Relabeling",
            description="",
            affected_groups=[3],
        )
        findings = Findings()
        findings.add(labeling)
        findings.add(relabeling)
        counts = findings.remediation_counts(total_groups=10)
        self.assertEqual(counts["relabel_fixable"], 3)
        self.assertEqual(counts["broken_source"], 1)
        self.assertEqual(counts["policy_issue"], 6)


class TestLabelingAnalyzer(unittest.TestCase):
    def _make_denial(self, tcontext_type, tcontext_mls="s0", count=1, permissive="0"):
        return {
            "count": count,
            "log": {
                "tcontext": f"system_u:object_r:{tcontext_type}:{tcontext_mls}",
                "scontext": "system_u:system_r:init_t:s0-s15:c0.c1023",
                "tclass": "file",
                "permissive": permissive,
            },
        }

    def test_detects_unlabeled_t(self):
        from analyzers.labeling import analyze_labeling
        denials = [self._make_denial("unlabeled_t", count=20) for _ in range(5)]
        findings = list(analyze_labeling(denials))
        self.assertTrue(any("unlabeled" in f.title.lower() for f in findings))

    def test_no_finding_for_normal_types(self):
        from analyzers.labeling import analyze_labeling
        denials = [self._make_denial("httpd_sys_content_t") for _ in range(5)]
        findings = list(analyze_labeling(denials))
        labeling_findings = [f for f in findings if "unlabeled" in f.title.lower()]
        self.assertEqual(len(labeling_findings), 0)

    def test_detects_mls_inconsistency(self):
        from analyzers.labeling import analyze_labeling
        system_types = ["etc_t", "lib_t", "bin_t", "ld_so_cache_t", "modules_dep_t", "modules_conf_t"]
        denials = [self._make_denial(t, tcontext_mls="s15:c0.c1023", count=10) for t in system_types]
        findings = list(analyze_labeling(denials))
        mls_findings = [f for f in findings if "MLS" in f.title or "level" in f.title.lower()]
        self.assertTrue(len(mls_findings) > 0)

    def test_unlabeled_threshold_below(self):
        from analyzers.labeling import analyze_labeling
        denials = [self._make_denial("unlabeled_t", count=1) for _ in range(2)]
        findings = list(analyze_labeling(denials))
        unlabeled = [f for f in findings if "unlabeled" in f.title.lower()]
        self.assertEqual(len(unlabeled), 0)


class TestRelabelingAnalyzer(unittest.TestCase):
    def test_detects_relabeling_denied(self):
        from analyzers.relabeling import analyze_relabeling
        denials = [{
            "count": 600,
            "log": {
                "scontext": "root:sysadm_r:semanage_t:s0-s15:c0.c1023",
                "tcontext": "system_u:object_r:semanage_store_t:s0",
                "tclass": "file",
                "permission": "relabelfrom",
                "comm": "genhomedircon",
            },
            "permissions": {"relabelfrom"},
        }]
        findings = list(analyze_relabeling(denials))
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)

    def test_no_finding_for_normal_denials(self):
        from analyzers.relabeling import analyze_relabeling
        denials = [{
            "count": 10,
            "log": {
                "scontext": "system_u:system_r:httpd_t:s0",
                "tcontext": "system_u:object_r:var_t:s0",
                "tclass": "file",
                "permission": "read",
                "comm": "httpd",
            },
            "permissions": {"read"},
        }]
        findings = list(analyze_relabeling(denials))
        self.assertEqual(len(findings), 0)


class TestBootImpactAnalyzer(unittest.TestCase):
    def test_detects_boot_blocking(self):
        from analyzers.boot_impact import analyze_boot_impact
        denials = [
            {"count": 50, "log": {"scontext": "system_u:system_r:kmod_t:s0-s15:c0.c1023", "tcontext": "system_u:object_r:modules_dep_t:s15:c0.c1023", "tclass": "file", "permission": "read", "permissive": "1"}},
            {"count": 20, "log": {"scontext": "system_u:system_r:mount_t:s0", "tcontext": "system_u:object_r:fixed_disk_device_t:s15:c0.c1023", "tclass": "blk_file", "permission": "getattr", "permissive": "1"}},
        ]
        findings = list(analyze_boot_impact(denials))
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)
        self.assertIn("boot", findings[0].title.lower())

    def test_no_boot_impact_for_application_denials(self):
        from analyzers.boot_impact import analyze_boot_impact
        denials = [
            {"count": 100, "log": {"scontext": "system_u:system_r:httpd_t:s0", "tcontext": "system_u:object_r:var_t:s0", "tclass": "file", "permission": "read", "permissive": "0"}},
        ]
        findings = list(analyze_boot_impact(denials))
        self.assertEqual(len(findings), 0)


class TestSystemicPatternAnalyzer(unittest.TestCase):
    def test_detects_systemic_pattern(self):
        from analyzers.patterns import analyze_systemic_patterns
        source_types = [
            "init_t", "kmod_t", "udev_t", "mount_t", "sshd_t",
            "httpd_t", "postfix_t", "chronyd_t", "avahi_t", "colord_t", "tuned_t",
        ]
        denials = [
            {"count": 10, "log": {"scontext": f"system_u:system_r:{st}:s0-s15:c0.c1023", "tcontext": "system_u:object_r:ld_so_cache_t:s15:c0.c1023", "tclass": "file", "permission": "read"}}
            for st in source_types
        ]
        findings = list(analyze_systemic_patterns(denials))
        self.assertTrue(len(findings) > 0)
        self.assertIn("systemic", findings[0].title.lower())

    def test_no_systemic_for_few_sources(self):
        from analyzers.patterns import analyze_systemic_patterns
        denials = [
            {"count": 10, "log": {"scontext": "system_u:system_r:httpd_t:s0", "tcontext": "system_u:object_r:var_t:s0", "tclass": "file", "permission": "read"}},
            {"count": 5, "log": {"scontext": "system_u:system_r:nginx_t:s0", "tcontext": "system_u:object_r:var_t:s0", "tclass": "file", "permission": "read"}},
        ]
        findings = list(analyze_systemic_patterns(denials))
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
