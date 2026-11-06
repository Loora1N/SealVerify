import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from sealverify import CheckResult, CheckSpec, CheckStatus, OverallStatus, VerificationReport


def spec(check_id="signature", object_id="seal-1", required=True):
    return CheckSpec(object_id, check_id, "示例检查", required)


def result(status=CheckStatus.PASSED, check_id="signature", object_id="seal-1"):
    return CheckResult(object_id, check_id, status, "合成检查结果")


class AggregationTests(unittest.TestCase):
    def test_all_required_checks_pass(self):
        report = VerificationReport("sample", (spec(), spec("chain")), (result(), result(check_id="chain")))
        self.assertEqual(report.overall_status, OverallStatus.PASSED)

    def test_failure_wins_over_error_and_missing_checks(self):
        report = VerificationReport(
            "sample", (spec(), spec("chain"), spec("hash")),
            (result(CheckStatus.FAILED), result(CheckStatus.ERROR, "chain")),
        )
        self.assertEqual(report.overall_status, OverallStatus.FAILED)
        self.assertEqual([item.check_id for item in report.missing_checks], ["hash"])
        self.assertEqual(len(report.results), 2)

    def test_optional_failure_also_fails_report(self):
        report = VerificationReport(
            "sample", (spec(), spec("timestamp", required=False)),
            (result(), result(CheckStatus.FAILED, "timestamp")),
        )
        self.assertEqual(report.overall_status, OverallStatus.FAILED)

    def test_required_uncertain_skipped_or_error_is_incomplete(self):
        for status in (CheckStatus.INDETERMINATE, CheckStatus.SKIPPED, CheckStatus.ERROR):
            with self.subTest(status=status):
                report = VerificationReport("sample", (spec(),), (result(status),))
                self.assertEqual(report.overall_status, OverallStatus.INCOMPLETE)

    def test_optional_unresolved_result_remains_visible_without_blocking_required_pass(self):
        for status in (CheckStatus.INDETERMINATE, CheckStatus.SKIPPED, CheckStatus.ERROR):
            with self.subTest(status=status):
                report = VerificationReport(
                    "sample", (spec(), spec("optional", required=False)),
                    (result(), result(status, "optional")),
                )
                self.assertEqual(report.overall_status, OverallStatus.PASSED)
                self.assertEqual(report.to_dict()["checks"][1]["status"], status.value)

    def test_missing_planned_check_prevents_partial_pass(self):
        for required in (True, False):
            with self.subTest(required=required):
                missing = spec("chain", required=required)
                report = VerificationReport("sample", (spec(), missing), (result(),))
                self.assertEqual(report.overall_status, OverallStatus.INCOMPLETE)
                self.assertEqual(report.missing_checks, (missing,))

    def test_no_plan_cannot_pass(self):
        self.assertEqual(VerificationReport("sample", ()).overall_status, OverallStatus.INCOMPLETE)

    def test_no_results_cannot_pass(self):
        self.assertEqual(VerificationReport("sample", (spec(),)).overall_status, OverallStatus.INCOMPLETE)

    def test_all_not_applicable_cannot_pass(self):
        report = VerificationReport("sample", (spec(),), (result(CheckStatus.NOT_APPLICABLE),))
        self.assertEqual(report.overall_status, OverallStatus.INCOMPLETE)

    def test_only_optional_checks_cannot_pass(self):
        report = VerificationReport("sample", (spec(required=False),), (result(),))
        self.assertEqual(report.overall_status, OverallStatus.INCOMPLETE)

    def test_not_applicable_does_not_block_other_required_pass(self):
        report = VerificationReport(
            "sample", (spec(), spec("timestamp")),
            (result(), result(CheckStatus.NOT_APPLICABLE, "timestamp")),
        )
        self.assertEqual(report.overall_status, OverallStatus.PASSED)

    def test_same_check_id_on_different_objects_is_not_overwritten(self):
        report = VerificationReport(
            "sample", (spec(), spec(object_id="seal-2")),
            (result(), result(CheckStatus.INDETERMINATE, object_id="seal-2")),
        )
        self.assertEqual(report.overall_status, OverallStatus.INCOMPLETE)
        self.assertEqual(report.to_dict()["summary"]["reported"], 2)


class ContractTests(unittest.TestCase):
    def test_duplicate_planned_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate planned"):
            VerificationReport("sample", (spec(), spec()))

    def test_duplicate_result_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate result"):
            VerificationReport("sample", (spec(),), (result(), result(CheckStatus.FAILED)))

    def test_result_outside_plan_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "declared plan"):
            VerificationReport("sample", (spec(),), (result(object_id="unknown"),))

    def test_status_strings_cannot_silently_bypass_enum(self):
        with self.assertRaises(TypeError):
            CheckResult("seal-1", "signature", "passed", "说明")

    def test_every_status_requires_a_reason(self):
        for status in CheckStatus:
            with self.subTest(status=status), self.assertRaises(ValueError):
                CheckResult("seal-1", "signature", status, "  ")

    def test_keys_labels_and_required_flag_are_validated(self):
        for args in (("", "check", "检查"), ("seal", " ", "检查"), ("seal", "check", "")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                CheckSpec(*args)
        with self.assertRaises(TypeError):
            spec(required="false")

    def test_naive_report_timestamp_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            VerificationReport("sample", (), generated_at=datetime(2026, 1, 1))

    def test_input_collections_are_snapshotted(self):
        plan, results = [spec()], [result()]
        report = VerificationReport("sample", plan, results)
        plan.clear()
        results.clear()
        self.assertEqual(report.overall_status, OverallStatus.PASSED)
        with self.assertRaises(FrozenInstanceError):
            report.source_name = "changed"

    def test_context_is_copied_and_read_only(self):
        context = {"证书来源": "合成数据"}
        item = CheckResult("seal-1", "chain", CheckStatus.INDETERMINATE, "缺少材料", context=context)
        context["证书来源"] = "changed"
        self.assertEqual(item.context["证书来源"], "合成数据")
        with self.assertRaises(TypeError):
            item.context["证书来源"] = "changed"
        item.to_dict()["context"]["证书来源"] = "changed"
        self.assertEqual(item.context["证书来源"], "合成数据")

    def test_non_text_context_and_detail_are_rejected(self):
        with self.assertRaises(TypeError):
            CheckResult("seal-1", "chain", CheckStatus.ERROR, "异常", context={"error": object()})
        with self.assertRaises(TypeError):
            CheckResult("seal-1", "chain", CheckStatus.ERROR, "异常", actual=object())

    def test_json_preserves_chinese_context_counts_and_missing_plan(self):
        item = CheckResult(
            "seal-1", "signature", CheckStatus.INDETERMINATE, "缺少验证材料",
            location="Doc_0/签章/证书", expected="可信证书链", actual="未提供信任锚",
            standard_reference="本测试的合成规则", remediation="补充材料",
            context={"材料来源": "合成"},
        )
        timestamp = datetime(2026, 11, 6, tzinfo=timezone.utc)
        report = VerificationReport("合成样例", (spec(), spec("hash")), (item,), timestamp)
        serialized = report.to_json()
        self.assertIn("合成样例", serialized)
        data = json.loads(serialized)
        self.assertEqual(data["overall_status"], "incomplete")
        self.assertEqual(data["generated_at"], "2026-11-06T00:00:00+00:00")
        self.assertEqual(data["summary"]["missing"], 1)
        self.assertEqual(data["summary"]["by_status"]["indeterminate"], 1)
        self.assertEqual(data["missing_checks"][0]["check_id"], "hash")
        self.assertEqual(data["checks"][0]["context"], {"材料来源": "合成"})
        self.assertEqual(data["checks"][0]["expected"], "可信证书链")
        self.assertEqual(data["checks"][0]["remediation"], "补充材料")


if __name__ == "__main__":
    unittest.main()
