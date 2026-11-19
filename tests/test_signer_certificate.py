from datetime import datetime, timezone
import hashlib
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from examples.create_maker_demo import issue, make_crl, rsa_identity
from examples.create_signed_demo import Signature
from examples.create_verified_demo import build_verified_demo
from sealverify.verification import verify_ofd
from test_inspection import VALUE_PATH, modify


AT = datetime(2026, 11, 19, tzinfo=timezone.utc)


class SignerCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = issue('root', AT, ca=True)
        cls.ca = issue('issuer', AT, ca=True, issuer=cls.root)
        cls.maker = issue('maker', AT, issuer=cls.ca)
        cls.first = issue('first signer', AT, issuer=cls.ca)
        cls.second = issue('second signer', AT, issuer=cls.ca)
        cls.chain = [('anchor', cls.root[0].public_bytes(Encoding.DER)),
                     ('intermediate', cls.ca[0].public_bytes(Encoding.DER))]
        cls.current = make_crl(cls.ca, AT)
        cls.ofd = cls.build(cls.first)

    @classmethod
    def build(cls, first):
        return build_verified_demo(algorithm='rsa', maker_identity=rsa_identity(cls.maker),
                                   signer_identities=[rsa_identity(first), rsa_identity(cls.second)])

    def verify(self, crl=None, data=None, *, no_materials=False):
        selected = self.current if crl is None else crl
        materials = [] if no_materials else self.chain + [('crl', selected.public_bytes(Encoding.DER))]
        report = verify_ofd(self.ofd if data is None else data, at=AT, materials=materials)
        return report, report['documents'][0]['signatures']

    def test_signer_source_and_positive_path_per_signature(self):
        report, sigs = self.verify()
        self.assertEqual(report['signer_certificate_validation']['checked_status'], 'passed')
        for sig, pair in zip(sigs, [self.first, self.second]):
            rep = sig['signer_certificate_validation']
            self.assertEqual(rep['certificate_sha256'], hashlib.sha256(pair[0].public_bytes(Encoding.DER)).hexdigest())
            self.assertEqual(rep['verification_time'], AT.isoformat())
            self.assertEqual([c['status'] for c in rep['checks']], ['passed'] * 4)
            self.assertTrue(all(c['location'] == sig['signed_value_path'] + '/cert' for c in rep['checks']))
            self.assertTrue(all('7.3 e)' in c['standard_reference'] for c in rep['checks']))
        self.assertEqual(report['verification_summary']['overall_status'], 'incomplete')

    def test_missing_materials_still_checks_certificate(self):
        report, sigs = self.verify(no_materials=True)
        self.assertEqual(report['signer_certificate_validation']['checked_status'], 'incomplete')
        self.assertEqual([c['status'] for c in sigs[0]['signer_certificate_validation']['checks']],
                         ['passed', 'passed', 'indeterminate', 'indeterminate'])

    def test_leaf_revoked_only_first_signer_needs_historical_review(self):
        report, sigs = self.verify(make_crl(self.ca, AT, revoked=self.first[0]))
        signer = sigs[0]['signer_certificate_validation']
        self.assertEqual(signer['checked_status'], 'failed')
        self.assertEqual(signer['signing_time_review_checks'], ['revocation'])
        self.assertIn('2026-11-18T00:00:00+00:00', signer['checks'][-1]['message'])
        self.assertFalse(signer['definitive_failure'])
        self.assertEqual(sigs[1]['signer_certificate_validation']['checked_status'], 'passed')
        self.assertEqual(report['maker_certificate_validation']['checked_status'], 'passed')
        self.assertEqual(report['m3_validation']['checked_status'], 'passed')
        self.assertEqual(report['verification_summary']['overall_status'], 'incomplete')

    def test_signer_and_maker_crls_can_come_from_different_issuers(self):
        other_ca = issue('other issuer', AT, ca=True, issuer=self.root)
        signer = issue('first signer', AT, issuer=other_ca)
        data = self.build(signer)
        materials = self.chain + [('intermediate', other_ca[0].public_bytes(Encoding.DER)),
                                  ('crl', self.current.public_bytes(Encoding.DER))]
        other_crl = ('crl', make_crl(other_ca, AT, revoked=signer[0]).public_bytes(Encoding.DER))
        for additional, expected in [([], 'indeterminate'), ([other_crl], 'failed')]:
            report = verify_ofd(data, at=AT, materials=materials + additional)
            first, second = report['documents'][0]['signatures']
            checks = {c['check_id']: c['status'] for c in first['signer_certificate_validation']['checks']}
            self.assertEqual(checks['path'], 'passed')
            self.assertEqual(checks['revocation'], expected)
            self.assertEqual(second['signer_certificate_validation']['checked_status'], 'passed')
            self.assertEqual(report['maker_certificate_validation']['checked_status'], 'passed')

    def test_leaf_expiry_in_path_and_usage_failure_have_distinct_effects(self):
        for signing in (True, False):
            with self.subTest(signing=signing):
                first = issue('expired', AT, issuer=self.ca, expired=True, signing=signing)
                report, sigs = self.verify(make_crl(self.ca, AT, revoked=first[0]), self.build(first))
                signer = sigs[0]['signer_certificate_validation']
                self.assertEqual(set(signer['signing_time_review_checks']), {'validity', 'revocation', 'path'})
                self.assertEqual(signer['definitive_failure'], not signing)
                self.assertEqual(report['verification_summary']['overall_status'], 'incomplete' if signing else 'failed')
                self.assertEqual(sigs[1]['signer_certificate_validation']['checked_status'], 'passed')

    def test_invalid_issuer_signature_is_a_definitive_path_failure(self):
        cert, private_key = self.first
        raw = bytearray(cert.public_bytes(Encoding.DER))
        raw[-1] ^= 1
        first = x509.load_der_x509_certificate(bytes(raw)), private_key
        report, sigs = self.verify(data=self.build(first))
        signer = sigs[0]['signer_certificate_validation']
        self.assertEqual({c['check_id']: c['status'] for c in signer['checks']}['path'], 'failed')
        self.assertEqual(signer['signing_time_review_checks'], [])
        self.assertTrue(signer['definitive_failure'])
        self.assertEqual(report['verification_summary']['overall_status'], 'failed')

    def test_unreadable_cert_does_not_substitute_authorized_cert_or_stop_later_checks(self):
        def change(raw):
            sig = Signature.load(raw)
            sig['cert'] = b'invalid'
            return sig.dump()
        report, sigs = self.verify(data=modify(self.ofd, {VALUE_PATH: change}))
        self.assertEqual([c['status'] for c in sigs[0]['signer_certificate_validation']['checks']], ['skipped'] * 4)
        for maker in sigs[0]['maker_certificate_validation'].values():
            self.assertEqual(maker['checked_status'], 'passed')
        self.assertEqual(sigs[1]['signer_certificate_validation']['checked_status'], 'passed')
        self.assertEqual(report['verification_summary']['overall_status'], 'failed')
