from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from asn1crypto import core
from PIL import Image

from examples.create_signed_demo import signature, build_signed_demo, certificate
from sealverify.cli import main
from sealverify.inspection import inspect_ofd
from sealverify.inspection.format import check_seal_format, check_signature_formats, frames, LimitError
from test_format import replace_field, tlv
from test_inspection import modify, VALUE_PATH, SIGNATURE_PATH


SEAL_PATH = VALUE_PATH.replace('SignedValue.dat', 'Seal.esl')


class SealFormatTests(unittest.TestCase):
    def seal(self, digest=False):
        return signature(digest_list=digest)['tbs']['seal']

    def check(self, raw=None):
        report = check_seal_format(self.seal().dump() if raw is None else raw)
        self.assertEqual(report['summary']['missing'], 0)
        self.assertEqual(report['summary']['planned'], report['summary']['reported'])
        self.assertEqual(report['cryptographic_verification'], 'not_performed')
        return report, {c['check_id']: c for c in report['checks']}

    def test_complete_structure_and_separate_capability_notes(self):
        for digest in (False, True):
            report, checks = self.check(self.seal(digest).dump())
            self.assertEqual(report['checked_status'], 'passed')
            self.assertEqual(report['overall_status'], 'incomplete')
            self.assertFalse(report['coverage']['complete'])
            self.assertNotIn('referenced_profiles', checks)
            self.assertEqual(checks['eSealInfo/picture/image']['status'], 'passed')
            self.assertEqual(report['header_version'], 4)

    def test_five_errors_keep_external_and_later_seals_checking(self):
        report = inspect_ofd(build_signed_demo(seal_errors=True, multiple_documents=True))
        first = report['documents'][0]['signatures'][0]
        seal = first['seal_format_validation']['embedded']
        failed = {c['check_id'] for c in seal['checks'] if c['status'] == 'failed'}
        self.assertEqual(failed, {'eSealInfo/header/id_value', 'eSealInfo/property/list_type',
            'eSealInfo/picture/image', 'cert/certificate', 'signedValue/encoding'})
        for doc in report['documents']:
            for sig in doc['signatures']:
                self.assertEqual(sig['seal_format_validation']['external']['checked_status'], 'passed')
        self.assertEqual(first['format_validation']['summary']['by_status']['failed'], 0)
        self.assertEqual(report['documents'][0]['signatures'][1]['seal_format_validation']['embedded']['checked_status'], 'passed')
        self.assertEqual(report['seal_format_validation']['resources_reported'], 6)
        self.assertEqual(report['seal_format_validation']['overall_status'], 'failed')

    def test_external_damage_is_independent_of_embedded(self):
        report = inspect_ofd(modify(build_signed_demo(), {SEAL_PATH: b'broken'}))
        seals = report['documents'][0]['signatures'][0]['seal_format_validation']
        self.assertEqual(seals['external']['checked_status'], 'failed')
        self.assertEqual(seals['embedded']['checked_status'], 'passed')

    def test_absent_missing_reference_and_unreadable_xml_differ(self):
        data = build_signed_demo()
        from zipfile import ZipFile
        with ZipFile(BytesIO(data)) as z:
            xml = z.read(SIGNATURE_PATH)
        absent = xml.replace(b'<ofd:Seal><ofd:BaseLoc>Seal.esl</ofd:BaseLoc></ofd:Seal>', b'')
        cases = [({SIGNATURE_PATH: absent}, 'absent', 'not_applicable'),
                 ({SEAL_PATH: None}, 'unavailable', 'incomplete'),
                 ({SIGNATURE_PATH: xml.replace(b'<ofd:BaseLoc>Seal.esl</ofd:BaseLoc>', b'')}, 'unavailable', 'incomplete'),
                 ({SIGNATURE_PATH: b'bad XML'}, 'unavailable', 'incomplete')]
        for changes, applicability, status in cases:
            with self.subTest(applicability=applicability, changes=list(changes)):
                report = inspect_ofd(modify(data, changes))
                result = report['documents'][0]['signatures'][0]['seal_format_validation']['external']
                self.assertEqual(result['applicability'], applicability)
                self.assertEqual(result['overall_status'], status)
                if applicability == 'unavailable':
                    self.assertEqual(next(c for c in result['checks'] if c['check_id'] == 'eSealInfo/extDatas')['status'], 'skipped')

    def test_bad_signed_value_still_checks_external(self):
        report = inspect_ofd(build_signed_demo(broken=True))
        seals = report['documents'][0]['signatures'][0]['seal_format_validation']
        self.assertEqual(seals['embedded']['applicability'], 'unavailable')
        self.assertEqual(seals['external']['checked_status'], 'passed')

    def test_missing_field_extra_field_trailing_data_and_wrong_container(self):
        raw = self.seal().dump()
        for damaged in (replace_field(raw, [3], None), raw + b'\x05\x00', b'\x04\x00', b'\x30\x80\x00\x00'):
            report, _ = self.check(damaged)
            self.assertEqual(report['checked_status'], 'failed')
        report, checks = self.check(replace_field(raw, [0, 0], b'\x04\x00'))
        self.assertEqual(checks['eSealInfo/header/structure']['status'], 'failed')
        self.assertEqual(checks['signedValue/encoding']['status'], 'passed')

    def test_unavailable_and_empty_bytes_are_distinct(self):
        self.assertEqual(check_seal_format(None)['checked_status'], 'incomplete')
        self.assertEqual(check_seal_format(b'')['checked_status'], 'failed')

    def test_certificate_list_bad_member_and_malformed_suffix_keep_prefix(self):
        entries = core.OctetString(b'broken').dump() + core.OctetString(certificate('Synthetic member', sm2=True)).dump()
        for suffix in (b'', b'\x04\x03\x01'):
            raw = replace_field(self.seal().dump(), [0, 2, 3], tlv(48, entries + suffix))
            _, checks = self.check(raw)
            self.assertEqual(checks['eSealInfo/property/certList/0/certificate']['status'], 'failed')
            self.assertEqual(checks['eSealInfo/property/certList/1/certificate']['status'], 'passed')
            self.assertEqual(checks['cert/certificate']['status'], 'passed')
            if suffix:
                self.assertEqual(checks['eSealInfo/property/certList']['status'], 'failed')

    def test_choice_mismatch_empty_list_and_limit(self):
        raw = self.seal(); raw['info']['property']['cert_type'] = 2
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['eSealInfo/property/certList/0/structure']['status'], 'failed')
        for entries, state in [(b'', 'failed'), (core.OctetString(b'bad').dump() * 65, 'indeterminate')]:
            _, checks = self.check(replace_field(self.seal().dump(), [0, 2, 3], tlv(48, entries)))
            self.assertEqual(checks['eSealInfo/property/certList']['status'], state)
            self.assertEqual(checks['signedValue/encoding']['status'], 'passed')
            if entries:
                self.assertEqual(checks['eSealInfo/property/certList/63/certificate']['status'], 'failed')

    def test_dates_validate_encoding_not_current_validity(self):
        raw = self.seal()
        for name in ('created', 'start', 'end'):
            raw['info']['property'][name] = '20000101000000Z'
        report, _ = self.check(raw.dump())
        self.assertEqual(report['checked_status'], 'passed')
        bad = replace_field(raw.dump(), [0, 2, 5], tlv(24, b'20260230000000Z'))
        _, checks = self.check(bad)
        self.assertEqual(checks['eSealInfo/property/validStart']['status'], 'failed')
        self.assertEqual(checks['eSealInfo/property/validEnd']['status'], 'passed')

    def test_extension_default_and_partial_list(self):
        extension = tlv(48, core.ObjectIdentifier('1.2.3.4').dump() + b'\x01\x01\x00\x04\x00')
        _, checks = self.check(replace_field(self.seal().dump(), [0, 4], tlv(48, extension + b'\x30\x05\x00')))
        self.assertEqual(checks['eSealInfo/extDatas/list']['status'], 'failed')
        self.assertEqual(checks['eSealInfo/extDatas/0/default']['status'], 'failed')
        self.assertEqual(checks['cert/certificate']['status'], 'passed')
        raw = self.seal(); del raw['info']['extensions']
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['eSealInfo/extDatas']['status'], 'not_applicable')
        raw = self.seal(); raw['info']['extensions'][0]['critical'] = True
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['eSealInfo/extDatas/0/meaning']['status'], 'indeterminate')

    def test_unknown_algorithm_bad_maker_and_rsa_encoding(self):
        raw = self.seal(); raw['algorithm'] = '1.2.3.999'
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['signAlgID/key_match']['status'], 'indeterminate')
        self.assertEqual(checks['signedValue/encoding']['status'], 'indeterminate')
        raw['algorithm'] = '1.2.840.113549.1.1.11'
        raw['cert'] = certificate('Synthetic RSA maker')
        raw['signature'] = bytes(range(256))
        report, _ = self.check(raw.dump())
        self.assertEqual(report['checked_status'], 'passed')
        raw['cert'] = b'broken'
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['signAlgID/key_match']['status'], 'skipped')
        self.assertEqual(checks['signedValue/encoding']['status'], 'passed')

    def test_raster_decoding_all_supported_formats_and_units(self):
        for kind in ('PNG', 'JPEG', 'GIF', 'BMP'):
            stream = BytesIO()
            Image.new('RGB', (3, 2), 'red').save(stream, format=kind)
            raw = self.seal()
            raw['info']['picture']['type'] = 'JPG' if kind == 'JPEG' else kind
            raw['info']['picture']['data'] = stream.getvalue()
            raw['info']['picture']['width'] = 40  # 毫米不是像素；不要求等于 3。
            _, checks = self.check(raw.dump())
            self.assertEqual(checks['eSealInfo/picture/image']['status'], 'passed')

    def test_bad_image_and_declared_type_do_not_hide_signature(self):
        raw = self.seal()
        damaged_png = bytearray(raw['info']['picture']['data'].native)
        damaged_png[damaged_png.index(b'IDAT') + 4] ^= 1
        for kind, data, expected in [('GIF', raw['info']['picture']['data'].native, 'failed'),
                                     ('PNG', bytes(damaged_png), 'failed'),
                                     ('PNG', b'broken', 'failed'), ('TIFF', b'unknown', 'indeterminate')]:
            raw['info']['picture']['type'] = kind
            raw['info']['picture']['data'] = data
            _, checks = self.check(raw.dump())
            self.assertEqual(checks['eSealInfo/picture/image']['status'], expected)
            self.assertEqual(checks['signedValue/encoding']['status'], 'passed')

    def test_svg_does_not_fetch_entities_or_claim_full_conformance(self):
        for xml, status in [(b'<svg xmlns="http://www.w3.org/2000/svg"/>', 'indeterminate'),
                            (b'<svg', 'failed'), (b'<html/>', 'failed'),
                            (b'<!DOCTYPE svg SYSTEM "https://example.invalid/x"><svg/>', 'indeterminate')]:
            raw = self.seal(); raw['info']['picture']['type'] = 'SVG'; raw['info']['picture']['data'] = xml
            _, checks = self.check(raw.dump())
            self.assertEqual(checks['eSealInfo/picture/image']['status'], status)

    def test_image_limits_and_decoder_fault_are_explicit(self):
        raw = self.seal(); raw['info']['picture']['data'] = b'x' * (4 * 1024 * 1024 + 1)
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['eSealInfo/picture/image']['status'], 'indeterminate')
        stream = BytesIO(); Image.new('1', (2001, 2000)).save(stream, format='PNG')
        raw['info']['picture']['data'] = stream.getvalue()
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['eSealInfo/picture/image']['status'], 'indeterminate')
        stream = BytesIO()
        animation = [Image.new('RGB', (2, 2), (i * 10, 0, 0)) for i in range(17)]
        animation[0].save(stream, format='GIF', save_all=True, append_images=animation[1:], duration=100)
        raw['info']['picture']['type'] = 'GIF'; raw['info']['picture']['data'] = stream.getvalue()
        _, checks = self.check(raw.dump())
        self.assertEqual(checks['eSealInfo/picture/image']['status'], 'indeterminate')
        with patch('sealverify.inspection.format.image_format', side_effect=RuntimeError('test')):
            _, checks = self.check()
        self.assertEqual(checks['eSealInfo/picture/image']['status'], 'error')
        self.assertEqual(checks['cert/certificate']['status'], 'passed')

    def test_long_form_length_does_not_reset_node_limit(self):
        with self.assertRaises(LimitError):
            list(frames(tlv(4, b'x' * 128) * 20001))

    def test_stage_separation_and_cli_raw_and_ofd(self):
        first, second = check_signature_formats(signature().dump())
        self.assertFalse(any(c['check_id'].startswith('toSign/eseal/header') for c in first['checks']))
        self.assertEqual(second['checked_status'], 'passed')
        with tempfile.TemporaryDirectory() as folder:
            for name, data, flags in [('seal.esl', self.seal().dump(), ['--seal']),
                                      ('signed.ofd', build_signed_demo(seal_errors=True), [])]:
                path = Path(folder) / name; path.write_bytes(data)
                with patch('sys.stdout', new_callable=StringIO) as out:
                    self.assertEqual(main(['check-seal-format', str(path), *flags]), 1)
                report = json.loads(out.getvalue())
                if flags:
                    self.assertEqual(report['checked_status'], 'passed')
                else:
                    self.assertEqual(report['seal_format_validation']['resources_reported'], 4)


if __name__ == '__main__':
    unittest.main()
