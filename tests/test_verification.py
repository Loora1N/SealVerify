from datetime import datetime, timezone
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from asn1crypto import x509

from examples.create_signed_demo import Signature, IntegerPair, CertList, DigestList, certificate
from examples.create_verified_demo import build_verified_demo
from examples.create_reading_demo import build_demo
from sealverify.cli import main
from sealverify.crypto import DEFAULT_SM2_ID, SM2_N, SM2_P, digest, hash_name, verify_signature
from sealverify.inspection.format import LimitError
from sealverify.verification import verify_ofd
from test_inspection import modify, VALUE_PATH, SIGNATURE_PATH
from test_format import replace_field


AT = datetime(2026, 11, 9, tzinfo=timezone.utc)
SEAL_PATH = VALUE_PATH.replace('SignedValue.dat', 'Seal.esl')
CONTENT_PATH = 'Doc_0/Pages/Page_0/Content.xml'


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = json.loads((Path(__file__).parent / 'fixtures/openssl-vectors.json').read_text())
        cls.vectors = [(bytes.fromhex(v['certificate_der']), v['algorithm'], bytes.fromhex(v['message_der']),
                        bytes.fromhex(v['signature'])) for v in data['vectors']]

    def test_independent_openssl_vectors_and_tampered_messages(self):
        for cert, oid, msg, sig in self.vectors:
            with self.subTest(oid=oid):
                self.assertTrue(verify_signature(cert, oid, msg, sig))
                with self.assertRaises(ValueError):
                    verify_signature(cert, oid, msg[:-1] + bytes([msg[-1] ^ 1]), sig)
                with self.assertRaises(ValueError):
                    verify_signature(cert, oid, msg, sig[:-1] + bytes([sig[-1] ^ 1]))

    def test_sm3_known_answer_and_fallback(self):
        expected = bytes.fromhex('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
        self.assertEqual(digest(b'abc', 'sm3'), expected)
        with patch('sealverify.crypto.hashlib.new', side_effect=ValueError):
            self.assertEqual(digest(b'abc', 'sm3'), expected)
        for name in ('SM3', '1.2.156.10197.1.401'):
            self.assertEqual(hash_name(name), 'sm3')
        with self.assertRaises(LimitError):
            hash_name('vendor-specific')

    def test_wrong_sm2_id_is_not_silently_retried(self):
        with self.assertRaises(ValueError):
            verify_signature(*self.vectors[0], sm2_id=b'wrong-id')

    def test_sm2_ranges_noncanonical_der_and_point_bounds(self):
        cert, oid, msg, _ = self.vectors[0]
        for r, s in [(0, 1), (-1, 2), (SM2_N, 1), (1, 0), (1, SM2_N), (SM2_N-1, 1)]:
            with self.subTest(r=r, s=s), self.assertRaises(ValueError):
                verify_signature(cert, oid, msg, IntegerPair({'r': r, 's': s}).dump())
        with self.assertRaises(ValueError):
            verify_signature(cert, oid, msg, b'\x30\x07\x02\x02\x00\x01\x02\x01\x02')
        for point in (b'\x04' + bytes(64), b'\x04' + SM2_P.to_bytes(32, 'big') + bytes(32)):
            bad = x509.Certificate.load(cert)
            bad['tbs_certificate']['subject_public_key_info']['public_key'] = point
            with self.assertRaises(ValueError):
                verify_signature(bad.dump(), oid, msg, IntegerPair({'r': 1, 's': 2}).dump())

    def test_sm2_infinity_equation_is_rejected(self):
        cert, oid, msg, _ = self.vectors[0]
        value = x509.Certificate.load(cert)
        # Public point G, not a private key. sG + (r+s)P = O for s=1, r=n-2.
        point = bytes.fromhex('0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
                              'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0')
        value['tbs_certificate']['subject_public_key_info']['public_key'] = point
        with self.assertRaises(ValueError):
            verify_signature(value.dump(), oid, msg, IntegerPair({'r': SM2_N-2, 's': 1}).dump())

    def test_unknown_algorithm_pss_and_rsa_length(self):
        cert, _, msg, sig = self.vectors[1]
        for oid in ('1.2.840.113549.1.1.10', '1.2.3.999'):
            with self.assertRaises(LimitError):
                verify_signature(cert, oid, msg, sig)
        with self.assertRaises(ValueError):
            verify_signature(cert, '1.2.840.113549.1.1.11', msg, sig[1:])
        with self.assertRaises(ValueError):
            verify_signature(self.vectors[0][0], '1.2.840.113549.1.1.11', msg, sig)


class VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.valid = build_verified_demo()
        cls.rsa = build_verified_demo(algorithm='rsa', digest_list=True)

    def check(self, data=None, **kwargs):
        report = verify_ofd(self.valid if data is None else data, at=AT, **kwargs)
        sigs = report['documents'][0]['signatures']
        first = sigs[0]['m3_validation']
        for s in sigs:
            self.assertEqual(s['m3_validation']['summary']['missing'], 0)
        return report, {c['check_id']: c for c in first['checks']}

    def change_value(self, fn, data=None):
        def mutate(raw):
            value = Signature.load(raw); fn(value); return value.dump()
        return modify(self.valid if data is None else data, {VALUE_PATH: mutate})

    def test_sm2_rsa_positive_and_m4_still_incomplete(self):
        for data in (self.valid, self.rsa):
            report, checks = self.check(data)
            self.assertEqual(report['m3_validation']['checked_status'], 'passed')
            self.assertEqual(report['m3_validation']['overall_status'], 'incomplete')
            for key in ('signature_value', 'seal/embedded/signature_value', 'seal/external/signature_value',
                        'authorization', 'document_digest', 'references/binding', 'seal_match'):
                self.assertEqual(checks[key]['status'], 'passed')
            self.assertFalse(report['documents'][0]['signatures'][0]['m3_validation']['coverage']['complete'])

    def test_tampered_content_does_not_stop_other_references(self):
        data = modify(self.valid, {CONTENT_PATH: lambda b: b + b'\n<!-- tamper -->'})
        report, checks = self.check(data)
        failures = [c for c in checks.values() if c['status'] == 'failed']
        self.assertEqual(len(failures), 1)
        self.assertTrue(failures[0]['check_id'].startswith('references/'))
        self.assertEqual(checks['signature_value']['status'], 'passed')
        self.assertEqual(checks['document_digest']['status'], 'passed')
        self.assertGreater(sum(c['status'] == 'passed' for k,c in checks.items() if k.endswith('/digest')), 1)

    def test_xml_whitespace_uses_original_bytes_not_canonicalization(self):
        _, checks = self.check(modify(self.valid, {SIGNATURE_PATH: lambda b: b + b'\n'}))
        self.assertEqual(checks['signature_value']['status'], 'passed')
        self.assertEqual(checks['document_digest']['status'], 'failed')
        self.assertEqual(checks['references/binding']['status'], 'skipped')

    def test_multi_error_and_second_signature_continue(self):
        def damage(v):
            v['signature'] = b'bad signature'
            v['tbs']['seal']['signature'] = b'bad seal signature'
            v['tbs']['seal']['info']['property']['certs'] = CertList([certificate('Unrelated certificate')])
            v['tbs']['hash'] = bytes(32)
        report, checks = self.check(self.change_value(damage))
        for key in ('signature_value', 'seal/embedded/signature_value', 'authorization', 'document_digest', 'seal_match'):
            self.assertEqual(checks[key]['status'], 'failed')
        self.assertEqual(checks['seal/external/signature_value']['status'], 'passed')
        self.assertEqual(report['documents'][0]['signatures'][1]['m3_validation']['checked_status'], 'passed')

    def test_unknown_protection_scope_does_not_guess_success(self):
        for prop, state in [('vendor:unknown', 'indeterminate'), ('/OFD.xml', 'indeterminate'), ('/../outside', 'failed')]:
            _, checks = self.check(self.change_value(lambda v: v['tbs'].__setitem__('property', prop)))
            self.assertEqual(checks['protected_scope']['status'], state)
            self.assertEqual(checks['document_digest']['status'], 'skipped')
            self.assertTrue(any(k.endswith('/digest') and c['status'] == 'passed' for k,c in checks.items()))

    def test_missing_signed_value_and_external_are_independent(self):
        for changes, expected in [({VALUE_PATH: None}, 'passed'), ({SEAL_PATH: None}, 'skipped')]:
            report, checks = self.check(modify(self.valid, changes))
            self.assertEqual(checks['seal/external/signature_value']['status'], expected)
            self.assertEqual(report['documents'][0]['signatures'][1]['m3_validation']['checked_status'], 'passed')

    def test_missing_referenced_resource_and_unknown_hash(self):
        _, checks = self.check(modify(self.valid, {CONTENT_PATH: None}))
        self.assertTrue(any(c['status'] == 'failed' for k,c in checks.items() if k.endswith('/digest')))
        _, checks = self.check(modify(self.valid, {SIGNATURE_PATH: lambda b: b.replace(b'CheckMethod="SM3"',b'CheckMethod="unknown"')}))
        self.assertEqual(checks['references/algorithm']['status'], 'indeterminate')
        self.assertTrue(all(c['status'] == 'skipped' for k,c in checks.items() if k.endswith('/digest')))

    def test_reference_transforms_and_path_escape_never_ignored(self):
        for before, after in [(b'<ofd:CheckValue>', b'<ofd:Transform/><ofd:CheckValue>'),
                              (b'FileRef="/Doc_0/', b'FileRef="/../../Doc_0/')]:
            _, checks = self.check(modify(self.valid, {SIGNATURE_PATH: lambda b: b.replace(before, after, 1)}))
            self.assertTrue(any(c['status'] in ('failed','indeterminate') for k,c in checks.items() if k.startswith('references/')))

    def test_digest_authorization_unknown_member_not_false_failure(self):
        def unknown(v):
            props=v['tbs']['seal']['info']['property']
            props['cert_type']=2
            props['certs']=DigestList([{'type':'vendorhash','value':bytes(32)}])
        _, checks = self.check(self.change_value(unknown))
        self.assertEqual(checks['authorization']['status'], 'indeterminate')
        self.assertEqual(checks['authorization/member/0']['status'], 'indeterminate')

    def test_digest_authorization_valid_match_after_unknown_member(self):
        def mixed(v):
            props=v['tbs']['seal']['info']['property']; props['cert_type']=2
            props['certs']=DigestList([{'type':'vendorhash','value':bytes(32)},
                {'type':'SM3','value':digest(v['cert'].native,'sm3')}])
        _, checks = self.check(self.change_value(mixed))
        self.assertEqual(checks['authorization']['status'], 'passed')
        self.assertEqual(checks['authorization/member/0']['status'], 'indeterminate')

    def test_declared_seal_period_uses_explicit_time(self):
        r = verify_ofd(self.valid, at=datetime(2040,1,1,tzinfo=timezone.utc))
        checks={c['check_id']:c for c in r['documents'][0]['signatures'][0]['m3_validation']['checks']}
        self.assertEqual(checks['seal/embedded/period']['status'],'failed')
        self.assertEqual(checks['signature_value']['status'],'passed')
        self.assertEqual(r['documents'][0]['signatures'][0]['m3_validation']['settings']['time_source'], 'caller')
        with self.assertRaises(ValueError): verify_ofd(self.valid, at=datetime(2026,1,1))

    def test_invalid_uid_and_wrong_uid(self):
        for uid in (b'', b'x'*8192):
            with self.assertRaises(ValueError): verify_ofd(self.valid, sm2_id=uid)
        _, checks = self.check(sm2_id=b'wrong')
        self.assertEqual(checks['signature_value']['status'],'failed')
        self.assertEqual(checks['document_digest']['status'],'passed')

    def test_unknown_algorithm_and_broken_tbs_keep_independent_checks(self):
        _, checks = self.check(self.change_value(lambda v:v.__setitem__('algorithm','1.2.3.999')))
        self.assertEqual(checks['signature_value']['status'],'indeterminate')
        self.assertEqual(checks['document/algorithm']['status'],'indeterminate')
        data=modify(self.valid,{VALUE_PATH:lambda b:replace_field(b,[0],b'\x30\x03\x02\x02\x01')})
        _, checks=self.check(data)
        self.assertEqual(checks['signature_value']['status'],'failed')
        self.assertEqual(checks['seal/external/signature_value']['status'],'passed')

    def test_backend_exception_records_error_and_continues(self):
        with patch('sealverify.verification.verify_signature',side_effect=RuntimeError('synthetic backend fault')):
            report,checks=self.check()
        self.assertEqual(checks['signature_value']['status'],'error')
        self.assertEqual(checks['document_digest']['status'],'passed')
        self.assertEqual(report['m3_validation']['signatures_checked'],2)

    def test_stage_exception_keeps_results_and_continues_same_signature(self):
        with patch('sealverify.verification.seal_checks', side_effect=RuntimeError('synthetic stage fault')):
            report, checks = self.check()
        self.assertEqual(checks['signature_value']['status'], 'passed')
        self.assertEqual(checks['seal/embedded/checker']['status'], 'error')
        self.assertEqual(checks['authorization']['status'], 'skipped')
        self.assertEqual(checks['document_digest']['status'], 'passed')
        self.assertEqual(report['m3_validation']['signatures_checked'], 2)

    def test_xml_selection_and_unknown_reference_configuration(self):
        for before, after, key, state in [
            (b'<ofd:SignedInfo>', b'<ofd:SignedInfo/><ofd:SignedInfo>', 'references/selection', 'failed'),
            (b'<ofd:References ', b'<ofd:References Transform="vendor" ', 'references/profile', 'indeterminate'),
            (b'<ofd:SignatureMethod>', b'<ofd:SignatureMethod>vendor', 'references/signature_method', 'indeterminate'),
        ]:
            _, checks = self.check(modify(self.valid, {SIGNATURE_PATH: lambda b: b.replace(before, after, 1)}))
            self.assertEqual(checks[key]['status'], state)
        _, checks = self.check(modify(self.valid, {SIGNATURE_PATH: lambda b: b.replace(
            b'<ofd:SignatureMethod>1.2.156.10197.1.501</ofd:SignatureMethod>', b'')}))
        self.assertEqual(checks['references/signature_method']['status'], 'not_applicable')

    def test_no_signatures_and_bad_package_cannot_pass(self):
        for data in (build_demo(), b'broken'):
            self.assertEqual(verify_ofd(data)['m3_validation']['checked_status'],'incomplete')

    def test_resource_budget_is_indeterminate_and_failure_is_not_lost_at_check_limit(self):
        with patch('sealverify.verification.MAX_VERIFY_READ_BYTES', 0):
            report, checks = self.check()
        self.assertEqual(checks['signed_value/resource']['status'], 'indeterminate')
        self.assertEqual(report['m3_validation']['checked_status'], 'incomplete')
        data = modify(self.valid, {CONTENT_PATH: lambda b: b + b'\n'})
        with patch('sealverify.inspection.format.MAX_CHECKS', 3):
            report, _ = self.check(data)
        first = report['documents'][0]['signatures'][0]['m3_validation']
        self.assertEqual(first['checked_status'], 'failed')
        self.assertGreater(first['omitted_checks']['failed'], 0)

    def test_cli_outputs_all_results_before_exit_and_original_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'signed.ofd'; file.write_bytes(self.valid)
            with patch('sys.stdout',new_callable=StringIO) as out:
                self.assertEqual(main(['verify',str(file)]),1)
            self.assertEqual(json.loads(out.getvalue())['m3_validation']['signatures_checked'],2)
            self.assertEqual(file.read_bytes(),self.valid)


if __name__ == '__main__':
    unittest.main()
