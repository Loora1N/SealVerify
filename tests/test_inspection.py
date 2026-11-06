from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
from zipfile import ZipFile

from examples.create_reading_demo import build_demo
from examples.create_signed_demo import build_signed_demo, signature, timestamp
from asn1crypto import cms
from sealverify.cli import main
from sealverify.inspection import inspect_ofd, resolve
from sealverify.inspection.asn1 import Decoder


SIGNATURE_PATH = 'Doc_0/Signs/Sign_0/Signature.xml'
VALUE_PATH = 'Doc_0/Signs/Sign_0/SignedValue.dat'


def modify(data, updates):
    output = BytesIO()
    with ZipFile(BytesIO(data)) as source, ZipFile(output, 'w') as target:
        for name in source.namelist():
            value = updates.get(name, source.read(name))
            if value is not None:
                target.writestr(name, value(source.read(name)) if callable(value) else value)
    return output.getvalue()


class InspectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = build_signed_demo()

    def first(self, report):
        return report['documents'][0]['signatures'][0]

    def test_two_signatures_and_page_mapping(self):
        report = inspect_ofd(self.sample)
        self.assertEqual(report['parse_status'], 'parsed')
        signatures = report['documents'][0]['signatures']
        self.assertEqual(len(signatures), 2)
        self.assertEqual([s['placements'][0]['page_number'] for s in signatures], [1, 4])
        self.assertEqual(signatures[1]['placements'][0]['page_box_mm'], [0, 0, 297, 210])
        self.assertEqual(signatures[0]['signed_value']['version'], 4)
        self.assertIn('Synthetic signer 1', signatures[0]['signed_value']['signer_certificate']['subject'])
        self.assertIn('Synthetic maker', signatures[0]['external_seal']['maker_certificate']['subject'])
        self.assertEqual(signatures[0]['verification'], 'not_performed')
        self.assertEqual(signatures[0]['references'][0]['verification'], 'not_performed')
        self.assertEqual(report['verification'], 'not_performed')
        self.assertTrue(signatures[0]['signed_value']['seal']['picture']['preview'].startswith('data:image/png;'))

    def test_timestamp_and_extensions_are_attributes_only(self):
        value = inspect_ofd(self.sample)['documents'][0]['signatures'][1]['signed_value']
        stamp = value['timestamp']['details']
        self.assertEqual(stamp['declared_time'], '2026-01-01T00:00:00+00:00')
        self.assertEqual(stamp['verification'], 'not_performed')
        self.assertEqual(stamp['signer_count'], 0)
        self.assertEqual(value['extensions'][0]['oid'], '1.2.3.4.5')
        self.assertEqual(value['seal']['extensions'][0]['critical'], False)

    def test_multiple_documents_do_not_mix_signatures(self):
        report = inspect_ofd(build_signed_demo(multiple_documents=True))
        self.assertEqual(report['parse_status'], 'parsed')
        self.assertEqual([len(d['signatures']) for d in report['documents']], [2, 1])
        self.assertEqual(report['documents'][1]['signatures'][0]['placements'][0]['page_id'], '900')

    def test_duplicate_index_pointers_are_deduplicated(self):
        data = modify(self.sample, {'Doc_0/Document.xml': lambda b: b.replace(b'</ofd:Document>', b'<ofd:Signatures>Signs/Signatures.xml</ofd:Signatures></ofd:Document>')})
        self.assertEqual(len(inspect_ofd(data)['documents'][0]['signatures']), 2)

    def test_timestamp_without_encapsulated_content_keeps_other_attributes(self):
        content = cms.ContentInfo.load(timestamp())
        del content['content']['encap_content_info']['content']
        value = signature(); value['timestamp'] = content.dump()
        report = inspect_ofd(modify(self.sample, {VALUE_PATH: value.dump()}))
        parsed = self.first(report)['signed_value']
        self.assertIsNone(parsed['timestamp']['details'])
        self.assertGreater(parsed['timestamp']['data']['bytes'], 0)
        self.assertEqual(parsed['version'], 4)
        self.assertTrue(parsed['signer_certificate']['subject'])
        self.assertEqual(report['parse_status'], 'partial')

    def test_broken_signature_preserves_other_signature_and_external_seal(self):
        report = inspect_ofd(build_signed_demo(broken=True))
        self.assertEqual(report['parse_status'], 'partial')
        signatures = report['documents'][0]['signatures']
        self.assertEqual(signatures[1]['parse_status'], 'parsed')
        self.assertIn('property', signatures[0]['external_seal'])
        self.assertTrue(signatures[0]['signed_value']['data']['bytes'])

    def test_broken_certificate_preserves_seal_and_signature_fields(self):
        data = modify(self.sample, {VALUE_PATH: signature(bad_certificate=True).dump()})
        value = self.first(inspect_ofd(data))['signed_value']
        self.assertEqual(value['algorithm'], '1.2.156.10197.1.501')
        self.assertEqual(value['seal']['property']['cert_list_type'], 1)
        self.assertNotIn('subject', value['signer_certificate'])

    def test_bad_scalar_preserves_adjacent_fields(self):
        raw = signature().dump().replace(b'20260101000000Z', b'20269901000000Z')
        report = inspect_ofd(modify(self.sample, {VALUE_PATH: raw}))
        value = self.first(report)['signed_value']
        self.assertIsNone(value['declared_time'])
        self.assertEqual(value['property_info'], 'synthetic coverage declaration')
        self.assertEqual(value['algorithm'], '1.2.156.10197.1.501')

    def test_certificate_digest_list_and_unknown_version(self):
        issues = []
        decoder = Decoder(lambda *args: issues.append(args))
        parsed = decoder.signature(signature(digest_list=True).dump(), 'test')
        self.assertEqual(parsed['seal']['property']['certificate_digests'][0]['type'], 'SHA256')
        self.assertEqual(issues, [])
        value = signature(); value['tbs']['version'] = 1
        parsed = decoder.signature(value.dump(), 'test')
        self.assertEqual(parsed['version'], 1)
        self.assertEqual(issues[-1][0], 'unsupported_signature')

    def test_missing_reference_and_bad_digest_do_not_hide_other_refs(self):
        data = modify(self.sample, {SIGNATURE_PATH: lambda b: b.replace(b'/OFD.xml', b'/missing.xml').replace(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', b'not-base64!')})
        report = inspect_ofd(data)
        ref = self.first(report)['references'][0]
        self.assertFalse(ref['present']); self.assertIsNone(ref['digest'])
        self.assertEqual(report['documents'][0]['signatures'][1]['parse_status'], 'parsed')

    def test_bad_boundary_and_unknown_page_disable_location(self):
        data = modify(self.sample, {SIGNATURE_PATH: lambda b: b.replace(b'PageRef="10"', b'PageRef="999"').replace(b'120 160 40 25', b'NaN 160 40 25')})
        placement = self.first(inspect_ofd(data))['placements'][0]
        self.assertIsNone(placement['boundary_mm']); self.assertIsNone(placement['page_number'])

    def test_duplicate_page_ids_are_not_guessed(self):
        data = modify(self.sample, {'Doc_0/Document.xml': lambda b: b.replace(b'ID="11" BaseLoc', b'ID="10" BaseLoc')})
        self.assertIsNone(self.first(inspect_ofd(data))['placements'][0]['page_number'])

    def test_missing_resource_and_malformed_xml_are_reported(self):
        for update in ({VALUE_PATH: None}, {SIGNATURE_PATH: b'<broken'}):
            with self.subTest(update=list(update)):
                report = inspect_ofd(modify(self.sample, update))
                self.assertEqual(report['parse_status'], 'partial')
                self.assertEqual(report['documents'][0]['signatures'][1]['parse_status'], 'parsed')

    def test_zip_duplicates_are_rejected_without_guessing(self):
        output = BytesIO(self.sample)
        with warnings.catch_warnings(), ZipFile(output, 'a') as archive:
            warnings.simplefilter('ignore', UserWarning)
            archive.writestr(VALUE_PATH, b'other')
        report = inspect_ofd(output.getvalue())
        self.assertEqual(report['parse_status'], 'partial')
        self.assertIsNone(self.first(report)['signed_value'])

    def test_optional_xml_time_and_algorithm_can_be_absent(self):
        def remove(data):
            for tag in ('SignatureMethod', 'SignatureDateTime'):
                start = data.index(('<ofd:' + tag + '>').encode())
                end_tag = ('</ofd:' + tag + '>').encode()
                end = data.index(end_tag) + len(end_tag)
                data = data[:start] + data[end:]
            return data
        report = inspect_ofd(modify(self.sample, {SIGNATURE_PATH: remove}))
        self.assertEqual(report['parse_status'], 'parsed')
        self.assertEqual(self.first(report)['declared_time'], '')
        self.assertTrue(self.first(report)['signed_value']['declared_time'])

    def test_missing_index_does_not_mean_unsigned_or_hide_other_document(self):
        sample = build_signed_demo(multiple_documents=True)
        report = inspect_ofd(modify(sample, {'Doc_0/Signs/Signatures.xml': None}))
        self.assertEqual(report['documents'][0]['parse_status'], 'partial')
        self.assertEqual(report['documents'][1]['parse_status'], 'parsed')
        self.assertEqual(len(report['documents'][1]['signatures']), 1)

    def test_dtd_and_external_entities_are_not_processed(self):
        data = modify(self.sample, {'OFD.xml': b'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///private">]><x>&secret;</x>'})
        report = inspect_ofd(data)
        self.assertEqual(report['parse_status'], 'error')
        self.assertTrue(report['issues'])

    def test_paths_stay_inside_zip(self):
        self.assertEqual(resolve('Doc/Signs/Signature.xml', '../../OFD.xml'), 'OFD.xml')
        self.assertEqual(resolve('Doc/Signs/Signature.xml', '/OFD.xml'), 'OFD.xml')
        for value in ('../../../private', 'https://example.com', 'C:\\private', '../..', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolve('Doc/Signature.xml', value)

    def test_malformed_container_and_unsupported_namespace(self):
        for data in (b'', b'not ZIP', modify(self.sample, {'OFD.xml': b'<OFD/>'})):
            with self.subTest(size=len(data)):
                self.assertEqual(inspect_ofd(data)['parse_status'], 'error')

    def test_empty_signature_list_is_not_verification_success(self):
        report = inspect_ofd(build_demo())
        self.assertEqual(report['parse_status'], 'parsed')
        self.assertEqual(report['documents'][0]['signatures'], [])
        self.assertEqual(report['verification'], 'not_performed')

    def test_active_image_format_has_no_inline_preview(self):
        value = signature(); picture = value['tbs']['seal']['info']['picture']
        picture['type'] = 'SVG'; picture['data'] = b'<svg onload="alert(1)"/>'
        report = inspect_ofd(modify(self.sample, {VALUE_PATH: value.dump()}))
        self.assertNotIn('preview', self.first(report)['signed_value']['seal']['picture'])
        self.assertTrue(any(i['code'] == 'image_preview_unavailable' for i in report['issues']))

    def test_page_box_falls_back_to_template_without_common_box(self):
        data = modify(self.sample, {'Doc_0/Document.xml': lambda b: b.replace(
            b'<ofd:PageArea><ofd:PhysicalBox>0 0 210 297</ofd:PhysicalBox></ofd:PageArea>', b'')})
        report = inspect_ofd(data)
        self.assertEqual(report['parse_status'], 'parsed')
        self.assertEqual(report['documents'][0]['pages'][0]['physical_box_mm'], [0, 0, 210, 297])
        self.assertEqual(report['documents'][0]['pages'][3]['physical_box_mm'], [0, 0, 297, 210])

    def test_limits_and_deep_asn1_fail_readably(self):
        with patch('sealverify.inspection.MAX_FILE_BYTES', 10):
            self.assertEqual(inspect_ofd(self.sample)['parse_status'], 'error')
        issues = []
        decoder = Decoder(lambda *args: issues.append(args))
        for raw in (b'\x30\x80\x00\x00', b'\x30\x82\xff\xff', b'\x30\x81\x00', b'\x30\x00junk'):
            self.assertNotIn('version', decoder.signature(raw, 'test'))
        self.assertEqual(len(issues), 4)
        raw = b'\x30\x00'
        for _ in range(40):
            raw = b'\x30' + bytes([len(raw)]) + raw
        self.assertNotIn('version', decoder.signature(raw, 'test'))
        self.assertIn('嵌套', issues[-1][2])

    def test_inspect_cli_json_and_nonverification_exit_codes(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / 'synthetic.ofd'
            for data, code in [(self.sample, 0), (b'broken', 1)]:
                file.write_bytes(data)
                with patch('sys.stdout', new_callable=StringIO) as stream:
                    self.assertEqual(main(['inspect', str(file)]), code)
                    self.assertEqual(json.loads(stream.getvalue())['verification'], 'not_performed')


if __name__ == '__main__':
    unittest.main()
