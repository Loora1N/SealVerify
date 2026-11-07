import unittest
from copy import deepcopy
from unittest.mock import patch

from asn1crypto import x509
from examples.create_signed_demo import certificate, signature, IntegerPair, sm2_value, build_signed_demo
from sealverify.inspection import inspect_ofd
from sealverify.inspection.asn1 import Decoder, SM2_SM3, RSA_SIGNATURE_OIDS
from tools.check_local_samples import snapshot, verify_signature_values


class SignatureValueTests(unittest.TestCase):
    def setUp(self):
        self.issues = []
        self.decoder = Decoder(lambda *args: self.issues.append(args))

    def decode(self, data, algorithm=SM2_SM3):
        return self.decoder.signature_value(data, algorithm, 'synthetic')['decoded']

    def test_sm2_signed_integer_padding_and_short_component(self):
        value = self.decode(sm2_value())
        self.assertEqual(value['r_hex'], '80' + '00' * 30 + '01')
        self.assertEqual(value['s_hex'], '00' * 31 + '02')
        self.assertEqual(value['status'], 'decoded')
        self.assertEqual(value['verification'], 'not_performed')
        self.assertNotIn('sha256', value)
        self.assertNotIn('hex_preview', value)
        self.assertEqual(self.issues, [])

    def test_sm2_variable_der_lengths_keep_all_digits(self):
        for r, s in [(1, 2), (1 << 255, 1 << 255), ((1 << 256) - 1, 0)]:
            with self.subTest(r=r):
                raw = IntegerPair({'r': r, 's': s}).dump()
                value = self.decode(raw)
                self.assertEqual(value['r_hex'], '%064x' % r)
                self.assertEqual(value['s_hex'], '%064x' % s)
        # 数学范围和签名正确性属于验签，本次零值也只按结构展示。
        self.assertEqual(self.issues, [])

    def test_sm2_invalid_der_never_guesses_rs(self):
        examples = [b'\x30\x06\x02\x01\x80\x02\x01\x01',  # negative
                    b'\x30\x07\x02\x02\x00\x01\x02\x01\x01',  # redundant zero
                    b'\x30\x06\x04\x01\x01\x02\x01\x01',  # wrong tag
                    b'\x30\x00', b'\x30\x80\x00\x00', sm2_value() + b'\x00',
                    sm2_value()[:-1], bytes(64), IntegerPair({'r': 1 << 256, 's': 1}).dump()]
        for raw in examples:
            with self.subTest(raw=raw.hex()):
                value = self.decode(raw)
                self.assertEqual(value['status'], 'error')
                self.assertNotIn('r_hex', value)
                self.assertNotIn('s_hex', value)
                self.assertEqual(value['signature_hex'], raw.hex())

    def test_rsa_complete_bytes_with_leading_zero_and_der_like_prefix(self):
        for oid in RSA_SIGNATURE_OIDS:
            for raw in (bytes(range(256)), sm2_value()):
                value = self.decode(raw, oid)
                self.assertEqual(value['algorithm'], 'RSA')
                self.assertEqual(value['signature_hex'], raw.hex())
                self.assertNotIn('r_hex', value)
        self.assertEqual(self.issues, [])

    def test_unknown_algorithm_keeps_full_value_without_guessing(self):
        for oid in ('1.2.3.4.5', None, '1.2.840.113549.1.1.1'):
            value = self.decode(bytes(range(256)), oid)
            self.assertEqual(value['status'], 'unsupported')
            self.assertEqual(value['signature_hex'], bytes(range(256)).hex())
            self.assertNotIn('r_hex', value)

    def test_empty_and_oversized_are_explicit_without_partial_preview(self):
        self.assertEqual(self.decode(b'')['status'], 'error')
        with patch('sealverify.inspection.asn1.MAX_SIGNATURE_BYTES', 8):
            value = self.decode(bytes(9), '1.2.840.113549.1.1.11')
        self.assertEqual(value['status'], 'unavailable')
        self.assertNotIn('signature_hex', value)
        self.assertNotIn('hex_preview', value)

    def test_certificate_uses_issuer_signature_algorithm_not_subject_key(self):
        cert = x509.Certificate.load(certificate('Synthetic subject with RSA key'))
        cert['signature_algorithm'] = {'algorithm': SM2_SM3}
        cert['tbs_certificate']['signature'] = {'algorithm': SM2_SM3}
        cert['signature_value'] = sm2_value(3)
        parsed = self.decoder.certificate(cert.dump(), 'synthetic/cert')
        self.assertEqual(parsed['public_key_algorithm'], '1.2.840.113549.1.1.1')
        value = parsed['certificate_signature']['decoded']
        self.assertEqual(value['algorithm'], 'SM2')
        self.assertEqual(value['s_hex'], '%064x' % 4)
        self.assertEqual(self.issues, [])

    def test_all_seal_and_certificate_roles_expose_signatures(self):
        value = self.decoder.signature(signature().dump(), 'synthetic/signature')
        self.assertIn('r_hex', value['signature']['decoded'])
        self.assertIn('r_hex', value['seal']['signature']['decoded'])
        for cert in [value['signer_certificate'], value['seal']['maker_certificate'],
                     *value['seal']['property']['certificates']]:
            self.assertEqual(cert['certificate_signature']['decoded']['algorithm'], 'RSA')
            self.assertEqual(cert['certificate_signature']['decoded']['signature_hex'], b'FAKE certificate signature'.hex())

    def test_broken_signature_does_not_discard_certificate_or_other_values(self):
        raw = signature(); raw['signature'] = b'bad DER'
        value = self.decoder.signature(raw.dump(), 'synthetic/signature')
        self.assertEqual(value['signature']['decoded']['status'], 'error')
        self.assertIn('subject', value['signer_certificate'])
        self.assertEqual(value['seal']['signature']['decoded']['status'], 'decoded')

    def test_baseline_projection_preserves_old_checks_and_new_value_is_checked(self):
        raw = build_signed_demo(); report = inspect_ofd(raw)
        self.assertEqual(verify_signature_values(raw, report), 16)
        changed = deepcopy(report)
        changed['documents'][0]['signatures'][0]['signed_value']['signature']['decoded']['s_hex'] = '00' * 32
        self.assertEqual(snapshot(changed), snapshot(report))
        with self.assertRaisesRegex(ValueError, '完整签名展示'):
            verify_signature_values(raw, changed)
        changed['documents'][0]['pages'][0]['number'] = 9
        self.assertNotEqual(snapshot(changed), snapshot(report))

    def test_new_certificate_signature_is_bound_to_original_certificate(self):
        raw = build_signed_demo(); report = inspect_ofd(raw)
        report['documents'][0]['signatures'][0]['signed_value']['signer_certificate']['certificate_signature']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, '原始证书'):
            verify_signature_values(raw, report)


if __name__ == '__main__':
    unittest.main()
