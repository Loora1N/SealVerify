from datetime import datetime, timezone
import unittest

from OpenSSL import SSL
from asn1crypto import crl as asn_crl, x509 as asn_cert
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from examples.create_maker_demo import issue, make_crl
from examples.create_verified_demo import identity
from sealverify.crypto import DEFAULT_SM2_ID
from sealverify.maker_certificate import Materials, Uncertain, check_maker, verify_crl_signature
from sealverify.reader import material_layout


AT = datetime(2026, 11, 19, tzinfo=timezone.utc)


def der(x):
    return x.public_bytes(Encoding.DER)


class MakerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = issue('root', AT, ca=True)
        cls.ca = issue('ca', AT, ca=True, issuer=cls.root)
        cls.leaf, _ = issue('maker', AT, issuer=cls.ca)
        cls.good = make_crl(cls.ca, AT)
        cls.ca_files = [('anchor', cls.root[0].public_bytes(Encoding.PEM)), ('intermediate', der(cls.ca[0]))]

    def statuses(self, entries, leaf=None):
        rep = check_maker(der(leaf or self.leaf), Materials(entries), AT, 'Seal.esl/cert', 'seal')
        return {row['check_id']: row['status'] for row in rep['checks']}

    def test_explicit_anchor_intermediate_and_current_crl(self):
        rows = self.statuses(self.ca_files + [('crl', der(self.good)), ('crl', self.good.public_bytes(Encoding.PEM))])
        self.assertEqual(list(rows.values()), ['passed'] * 4)

    def test_sm2_issuer_path_and_direct_crl(self):
        raw, sign, oid, _ = identity('SM2 CA', 'sm2', DEFAULT_SM2_ID)
        key_info = asn_cert.Certificate.load(raw)['tbs_certificate']['subject_public_key_info']
        # 使用同一个 SM2 CA 签发叶证书和 CRL。临时密钥只在内存中使用。
        def sign_cert(template, is_ca):
            obj = asn_cert.Certificate.load(der(template))
            tbs = obj['tbs_certificate']
            if is_ca:
                tbs['subject_public_key_info'] = key_info
            for ext in tbs['extensions']:
                if is_ca and ext['extn_id'].native == 'key_identifier':
                    ext['extn_value'] = key_info.sha1
                if ext['extn_id'].native == 'authority_key_identifier':
                    ext['extn_value'] = asn_cert.AuthorityKeyIdentifier({'key_identifier': key_info.sha1})
            tbs['signature'] = obj['signature_algorithm'] = {'algorithm': oid}
            obj['signature_value'] = sign(tbs.dump())
            return x509.load_der_x509_certificate(obj.dump())

        ca = sign_cert(self.root[0], True)
        template, _ = issue('SM2-issued maker', AT, issuer=self.root)
        maker = sign_cert(template, False)
        for revoked, expected in [(None, 'passed'), (template, 'failed')]:
            obj = asn_crl.CertificateList.load(der(make_crl(self.root, AT, revoked=revoked)))
            tbs = obj['tbs_cert_list']
            for ext in tbs['crl_extensions']:
                if ext['extn_id'].native == 'authority_key_identifier':
                    ext['extn_value'] = asn_cert.AuthorityKeyIdentifier({'key_identifier': key_info.sha1})
            tbs['signature'] = obj['signature_algorithm'] = {'algorithm': oid}
            obj['signature'] = sign(tbs.dump())
            crl = x509.load_der_x509_crl(obj.dump())
            verify_crl_signature(crl, ca)
            rows = self.statuses([('anchor', der(ca)), ('crl', der(crl))], maker)
            if SSL.OPENSSL_VERSION_NUMBER >= 0x40000000:
                self.assertEqual(rows['path'], 'passed')
                self.assertEqual(rows['revocation'], expected)
            else:
                # 旧后端的证书签名默认 SM2 ID 可能为空。无法建链时保留证据不足。
                self.assertIn((rows['path'], rows['revocation']), [('passed', expected), ('indeterminate', 'indeterminate')])
            obj['signature'] = sign(b'wrong payload')
            with self.assertRaises(Uncertain):
                verify_crl_signature(x509.load_der_x509_crl(obj.dump()), ca)

    def test_intermediate_is_not_trusted_missing_ca_and_empty_input(self):
        for files in ([], self.ca_files[1:], self.ca_files[:1], [('intermediate', der(self.root[0]))] + self.ca_files[1:]):
            statuses = self.statuses(files + [('crl', der(self.good))])
            self.assertEqual(list(statuses.values()), ['passed','passed','indeterminate','indeterminate'])

    def test_invalid_crls_cannot_prove_good_or_revoked(self):
        for crl in (make_crl(self.ca, AT, stale=True), make_crl(self.root, AT), make_crl(self.ca, AT, sign_with=self.root[1], revoked=self.leaf),
                    make_crl(self.ca, AT, extra=x509.DeltaCRLIndicator(1))):
            statuses = self.statuses(self.ca_files + [('crl', der(crl))])
            self.assertEqual(statuses['path'], 'passed')
            self.assertEqual(statuses['revocation'], 'indeterminate')

    def test_positive_revocation_and_ambiguous_crls(self):
        revoked = ('crl', der(make_crl(self.ca, AT, revoked=self.leaf)))
        self.assertEqual(self.statuses(self.ca_files + [revoked])['revocation'], 'failed')
        self.assertEqual(self.statuses(self.ca_files + [('crl', b'bad'), revoked])['revocation'], 'failed')
        self.assertEqual(self.statuses(self.ca_files + [revoked, ('crl', der(self.good))])['revocation'], 'indeterminate')

    def test_expired_leaf_does_not_hide_revocation_or_wrong_usage(self):
        expired, _ = issue('expired', AT, issuer=self.ca, expired=True, signing=False)
        rows = self.statuses(self.ca_files + [('crl', der(make_crl(self.ca, AT, revoked=expired)))], expired)
        self.assertEqual(list(rows.values()), ['failed'] * 4)

    def test_missing_usage_and_restricted_eku(self):
        for opts in ({'signing': None}, {'eku': [ExtendedKeyUsageOID.SERVER_AUTH]}):
            leaf, _ = issue('usage', AT, issuer=self.ca, **opts)
            self.assertEqual(self.statuses(self.ca_files, leaf)['key_usage'], 'indeterminate')

    def test_bad_material_and_absent_vs_missing(self):
        mats = Materials([('anchor', b'garbage'), ('intermediate', der(self.leaf)), ('crl', b'bad')])
        self.assertTrue(all(i['status']=='unavailable' for i in mats.inventory))
        for absent, expected in [(True, 'not_applicable'), (False, 'skipped')]:
            report = check_maker(None, mats, AT, 'Seal.esl', 'seal', absent=absent)
            self.assertEqual([c['status'] for c in report['checks']], [expected] * 4)

    def test_material_frame_limits(self):
        self.assertEqual(material_layout('[["crl",100]]'), [['crl', 100]])
        for data in ('{"crl":2}', '[["crl",-1]]', '[["ca",2]]','[["crl",true]]','[["anchor",131073]]'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                material_layout(data)
