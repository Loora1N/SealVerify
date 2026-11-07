from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from asn1crypto import core
from examples.create_signed_demo import signature, certificate, build_signed_demo, Extension, Extensions
from examples.create_reading_demo import build_demo
from sealverify.cli import main
from sealverify.inspection import inspect_ofd
from sealverify.inspection.format import check_signature_format, frames, FormatChecker
from tools.check_local_samples import verify_format_results
from test_inspection import modify, VALUE_PATH, SIGNATURE_PATH


def tlv(tag, content):
    size = len(content)
    length = bytes([size]) if size < 128 else bytes([128 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + content


def replace_field(data, path, value):
    node = list(frames(data))[0]
    items = [child.raw for child in frames(node.content)]
    if len(path) == 1:
        if value is None:
            del items[path[0]]
        else:
            items[path[0]] = value
    else:
        items[path[0]] = replace_field(items[path[0]], path[1:], value)
    return tlv(node.tag, b''.join(items))


class FormatTests(unittest.TestCase):
    def check(self, raw=None):
        report = check_signature_format(signature().dump() if raw is None else raw)
        self.assertEqual(report['summary']['missing'], 0)
        self.assertEqual(report['summary']['planned'], report['summary']['reported'])
        self.assertEqual(report['cryptographic_verification'], 'not_performed')
        return report, {item['check_id']: item for item in report['checks']}

    def test_valid_structure_keeps_manual_review_and_no_crypto_claim(self):
        report, checks = self.check()
        self.assertEqual(report['overall_status'], 'incomplete')
        self.assertEqual({key for key, c in checks.items() if c['status'] == 'indeterminate'},
                         {'property_scope', 'referenced_profiles'})
        self.assertEqual(report['summary']['by_status']['failed'], 0)
        self.assertEqual(checks['signatureAlgID/key_match']['status'], 'passed')
        self.assertEqual(checks['timeStamp']['status'], 'not_applicable')

    def test_multiple_faults_and_second_signature_are_all_reported(self):
        report = inspect_ofd(build_signed_demo(format_errors=True))
        first, second = [s['format_validation'] for s in report['documents'][0]['signatures']]
        failed = {c['check_id'] for c in first['checks'] if c['status'] == 'failed'}
        self.assertTrue({'version_match', 'cert/certificate', 'sm3_length', 'signatureValue/encoding',
                         'toSign/eseal/header/id_value', 'toSign/propertyInfo'} <= failed)
        self.assertEqual(next(c for c in first['checks'] if c['check_id'] == 'property_scope')['status'], 'skipped')
        self.assertEqual(second['summary']['by_status']['failed'], 0)
        self.assertEqual(report['format_validation']['signatures_checked'], 2)
        self.assertEqual(report['format_validation']['overall_status'], 'failed')

    def test_bad_nested_seal_does_not_hide_outer_certificate_and_signature(self):
        raw = replace_field(signature().dump(), [0, 1], b'\x30\x03\x02\x02\x01')
        _, checks = self.check(raw)
        self.assertEqual(checks['toSign/eseal/structure']['status'], 'failed')
        for key in ('toSign/timeInfo', 'cert/certificate', 'signatureValue/encoding'):
            self.assertEqual(checks[key]['status'], 'passed')
        self.assertEqual(checks['toSign/eseal/extDatas']['status'], 'skipped')

    def test_truncated_tbs_keeps_prefix_and_outer_independent_fields(self):
        raw = replace_field(signature().dump(), [0], tlv(48, b'\x02\x01\x04\x30\x05\x00'))
        _, checks = self.check(raw)
        self.assertEqual(checks['toSign/structure']['status'], 'failed')
        self.assertEqual(checks['toSign/version']['status'], 'passed')
        self.assertEqual(checks['toSign/timeInfo']['status'], 'skipped')
        self.assertEqual(checks['cert/certificate']['status'], 'passed')

    def test_missing_required_field_and_optional_absence_differ(self):
        raw = signature(); del raw['tbs']['extensions']
        _, checks = self.check(replace_field(raw.dump(), [0, 4], None))
        self.assertEqual(checks['toSign/propertyInfo/presence']['status'], 'failed')
        self.assertEqual(checks['toSign/extDatas']['status'], 'not_applicable')
        self.assertEqual(checks['cert/certificate']['status'], 'passed')

    def test_wrong_type_and_nonminimal_integer_keep_other_checks(self):
        for value in (b'\x04\x01\x04', b'\x02\x02\x00\x04', b'\x02\x00'):
            with self.subTest(value=value):
                _, checks = self.check(replace_field(signature().dump(), [0, 0], value))
                self.assertEqual(checks['toSign/version']['status'], 'failed')
                self.assertEqual(checks['cert/certificate']['status'], 'passed')

    def test_versions_and_id_are_explicit_constraints(self):
        raw = signature(); raw['tbs']['version'] = 3
        raw['tbs']['seal']['info']['header']['version'] = 3
        raw['tbs']['seal']['info']['header']['id'] = 'XX'
        _, checks = self.check(raw.dump())
        for key in ('version_match', 'toSign/eseal/header/version_value', 'toSign/eseal/header/id_value'):
            self.assertEqual(checks[key]['status'], 'failed')

    def test_der_time_calendar_timezone_precision(self):
        for value, expected in [(b'20260101000000Z', 'passed'), (b'20260101000000.1Z', 'passed'),
                                (b'20260230000000Z', 'failed'), (b'20260101000000+0000', 'failed'),
                                (b'202601010000Z', 'failed'), (b'20260101000000.10Z', 'failed')]:
            with self.subTest(value=value):
                _, checks = self.check(replace_field(signature().dump(), [0, 2], tlv(24, value)))
                self.assertEqual(checks['toSign/timeInfo']['status'], expected)
                self.assertEqual(checks['signatureValue/encoding']['status'], 'passed')

    def test_bad_bit_padding_nonbyte_aligned_and_empty_hash(self):
        for content in (b'\x01\x01', b'\x01\x02', b'\x00'):
            _, checks = self.check(replace_field(signature().dump(), [0, 3], tlv(3, content)))
            self.assertEqual(checks['toSign/dataHash']['status'], 'failed')
            self.assertEqual(checks['sm3_length']['status'], 'skipped')

    def test_empty_list_and_unknown_choice_are_not_silently_accepted(self):
        raw = signature(); raw['tbs']['seal']['info']['property']['cert_type'] = 9
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['toSign/eseal/property/list_type']['status'], 'failed')
        self.assertEqual(checks['toSign/eseal/property/certList/0']['status'], 'skipped')
        raw = replace_field(signature().dump(), [0, 1, 0, 2, 3], b'\x30\x00')
        _, checks = self.check(raw)
        self.assertEqual(checks['toSign/eseal/property/certList']['status'], 'failed')

    def test_digest_choice_and_empty_optional_extensions(self):
        raw = signature(digest_list=True); raw['tbs']['extensions'] = Extensions([])
        report, checks = self.check(raw.dump())
        self.assertEqual(report['summary']['by_status']['failed'], 0)
        self.assertEqual(checks['toSign/eseal/property/certList/0/type']['status'], 'passed')
        self.assertEqual(checks['toSign/extDatas/list']['status'], 'passed')

    def test_extensions_default_false_and_unknown_critical_semantics(self):
        extension = tlv(48, core.ObjectIdentifier('1.2.3.4').dump() + b'\x01\x01\x00\x04\x00')
        raw = replace_field(signature().dump(), [0, 5], tlv(160, tlv(48, extension)))
        _, checks = self.check(raw)
        self.assertEqual(checks['toSign/extDatas/0/default']['status'], 'failed')
        raw = signature(); raw['tbs']['extensions'][0]['critical'] = True
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['toSign/extDatas/0/meaning']['status'], 'indeterminate')

    def test_optional_tag_wrong_encoding_does_not_hide_certificate(self):
        for value in (b'\x80\x00', b'\xa0\x00', b'\xa0\x04\x30\x00\x30\x00'):
            _, checks = self.check(replace_field(signature().dump(), [0, 5], value))
            self.assertEqual(checks['toSign/extDatas/tag']['status'], 'failed')
            self.assertEqual(checks['cert/certificate']['status'], 'passed')

    def test_certificate_failure_skips_key_match_but_keeps_signature_encoding(self):
        _, checks = self.check(signature(bad_certificate=True).dump())
        self.assertEqual(checks['cert/certificate']['status'], 'failed')
        self.assertEqual(checks['signatureAlgID/key_match']['status'], 'skipped')
        self.assertEqual(checks['signatureValue/encoding']['status'], 'passed')

    def test_algorithm_matches_subject_key_not_issuer_signature_algorithm(self):
        raw = signature(); raw['cert'] = certificate('Synthetic RSA subject')
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['signatureAlgID/key_match']['status'], 'failed')
        report, checks = self.check(signature(rsa=True).dump())
        self.assertEqual(checks['signatureAlgID/key_match']['status'], 'passed')
        self.assertEqual(report['summary']['by_status']['failed'], 0)

    def test_unknown_algorithm_and_bad_oid_are_different(self):
        raw = signature(); raw['algorithm'] = '1.2.3.999'
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['signatureAlgID/key_match']['status'], 'indeterminate')
        self.assertEqual(checks['signatureValue/encoding']['status'], 'indeterminate')
        _, checks = self.check(replace_field(signature().dump(), [2], b'\x06\x02\x80\x2a'))
        self.assertEqual(checks['signatureAlgID/oid']['status'], 'failed')

    def test_timestamp_present_invalid_and_absent_are_different(self):
        _, checks = self.check(signature(with_timestamp=True).dump())
        self.assertEqual(checks['timeStamp/container']['status'], 'failed')  # 合成 CMS 故意无签名者
        self.assertIn('签名者', checks['timeStamp/container']['message'])
        raw = signature(with_timestamp=True); raw['timestamp'] = b'bad timestamp'
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['timeStamp/container']['status'], 'failed')
        self.assertEqual(checks['signatureValue/encoding']['status'], 'passed')

    def test_outer_garbage_and_extra_fields_are_reported_without_hiding_prefix(self):
        raw = signature().dump()
        for data in (raw + b'\x05\x00', tlv(48, list(frames(raw))[0].content + b'\x05\x00\x05\x00')):
            report, checks = self.check(data)
            self.assertEqual(report['overall_status'], 'failed')
            self.assertEqual(checks['cert/certificate']['status'], 'passed')

    def test_unavailable_or_broken_container_never_claims_optional_fields_absent(self):
        for data in (None, b'', b'broken', b'\x30\x80\x00\x00'):
            report = check_signature_format(data)
            checks = {c['check_id']: c for c in report['checks']}
            self.assertNotEqual(report['overall_status'], 'passed')
            self.assertEqual(checks['timeStamp']['status'], 'skipped')

    def test_resource_failure_continues_other_signature_and_documents(self):
        data = build_signed_demo(multiple_documents=True)
        for updates in ({VALUE_PATH: None}, {SIGNATURE_PATH: b'broken'}):
            report = inspect_ofd(modify(data, updates))
            values = [s['format_validation'] for d in report['documents'] for s in d['signatures']]
            self.assertEqual(len(values), 3)
            self.assertEqual(values[0]['checks'][0]['check_id'], 'resource')
            self.assertEqual(values[-1]['summary']['by_status']['failed'], 0)

    def test_internal_seal_checker_error_continues_outer_checks(self):
        with patch.object(FormatChecker, 'seal', side_effect=RuntimeError('synthetic bug')):
            _, checks = self.check()
        self.assertEqual(checks['embedded_seal_error']['status'], 'error')
        self.assertEqual(checks['cert/certificate']['status'], 'passed')
        self.assertEqual(checks['signatureValue/encoding']['status'], 'passed')

    def test_limits_preserve_failure_counts_and_do_not_claim_success(self):
        raw = signature(); raw['tbs']['version'] = 3
        with patch('sealverify.inspection.format.MAX_CHECKS', 2):
            report = check_signature_format(raw.dump())
        self.assertEqual(report['overall_status'], 'failed')
        self.assertGreater(report['omitted_checks']['failed'], 0)
        self.assertEqual(report['checks'][-1]['check_id'], 'check_limit')

    def test_no_signature_or_unreadable_package_is_not_format_success(self):
        for data in (build_demo(), b'broken'):
            report = inspect_ofd(data)
            self.assertEqual(report['format_validation']['overall_status'], 'incomplete')
            self.assertEqual(report['format_validation']['signatures_checked'], 0)

    def test_cli_prints_every_signature_before_nonzero_result(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'synthetic.ofd'; path.write_bytes(build_signed_demo(format_errors=True))
            with patch('sys.stdout', new_callable=StringIO) as output:
                self.assertEqual(main(['check-format', str(path)]), 1)
            report = json.loads(output.getvalue())
            self.assertEqual(len(report['documents'][0]['signatures']), 2)
            self.assertEqual(report['format_validation']['overall_status'], 'failed')

    def test_baseline_new_format_checks_cannot_be_dropped_or_changed(self):
        data = build_signed_demo(format_errors=True)
        raw = signature(); del raw['tbs']['extensions']; del raw['tbs']['seal']['info']['extensions']
        data = modify(data, {VALUE_PATH: raw.dump()})
        report = inspect_ofd(data)
        self.assertEqual(verify_format_results(report), 2)
        changed = deepcopy(report)
        changed['documents'][0]['signatures'][0]['format_validation']['checks'][0]['status'] = 'failed'
        with self.assertRaises(ValueError):
            verify_format_results(changed)
        changed = deepcopy(report)
        checks = changed['documents'][0]['signatures'][0]['format_validation']['checks']
        checks[:] = [c for c in checks if c['check_id'] != 'sm3_length']
        with self.assertRaises(ValueError):
            verify_format_results(changed)


if __name__ == '__main__':
    unittest.main()
