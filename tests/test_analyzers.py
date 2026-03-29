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


if __name__ == "__main__":
    unittest.main()
