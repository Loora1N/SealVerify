from io import BytesIO
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from zipfile import ZipFile

from sealverify.reader import ReaderServer, WEB_ROOT, read_document


class ReaderServerTests(unittest.TestCase):
    def setUp(self):
        self.document = WEB_ROOT.joinpath('demo.ofd').read_bytes()
        self.server = ReaderServer(document=self.document, name='合成示例.ofd')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.cleanup_server)

    def cleanup_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, resource='', **kwargs):
        return urlopen(Request(self.server.url + resource, **kwargs), timeout=5)

    def test_html_and_offline_dependencies_are_packaged(self):
        for asset in ('', 'reader.js', 'reader.css', 'vendor/viewer.css',
                      'vendor/THIRD_PARTY_NOTICES.txt', 'fonts/NotoSansCJKsc-Regular.otf',
                      'fonts/OFL.txt', 'demo.ofd'):
            with self.subTest(asset=asset), self.request(asset) as response:
                self.assertEqual(response.status, 200)
                self.assertGreater(int(response.headers['Content-Length']), 0)
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
                self.assertIn("connect-src 'self' blob:", response.headers['Content-Security-Policy'])

    def test_explicit_document_is_served_without_modification(self):
        with self.request('session.json') as response:
            self.assertEqual(json.load(response), {'name': '合成示例.ofd', 'hasDocument': True})
        with self.request('document.ofd') as response:
            self.assertEqual(response.read(), self.document)

    def test_arbitrary_paths_and_tokenless_access_are_denied(self):
        for path in ('../PROMPT.md', '%2e%2e/PROMPT.md', '/etc/passwd', '.git/config',
                     'fonts/../../../PROMPT.md', 'session.json/anything'):
            with self.subTest(path=path), self.assertRaises(HTTPError) as error:
                self.request(path)
            self.assertEqual(error.exception.code, 404)
        with self.assertRaises(HTTPError) as error:
            urlopen('http://' + self.server.authority + '/', timeout=5)
        self.assertEqual(error.exception.code, 404)

    def test_foreign_host_and_origin_are_denied(self):
        for headers in ({'Host': 'example.com'}, {'Origin': 'https://example.com'}):
            with self.subTest(headers=headers), self.assertRaises(HTTPError) as error:
                self.request(headers=headers)
            self.assertEqual(error.exception.code, 403)

    def test_does_not_accept_document_uploads(self):
        with self.assertRaises(HTTPError) as error:
            self.request('upload', data=b'private')
        self.assertEqual(error.exception.code, 405)

    def test_inspection_endpoint_returns_json_without_persisting_input(self):
        with self.request('inspect', data=self.document, headers={'Content-Type': 'application/ofd'}) as response:
            report = json.load(response)
        self.assertEqual(report['parse_status'], 'parsed')
        self.assertEqual(report['verification'], 'not_performed')
        self.assertEqual(len(report['documents'][0]['pages']), 4)
        self.assertEqual(self.server.document, self.document)

    def test_inspection_refuses_foreign_origin_size_and_type(self):
        for headers, expected in [({'Content-Type': 'text/plain'}, 415),
                                  ({'Content-Type': 'application/ofd', 'Origin': 'https://example.com'}, 403),
                                  ({'Content-Type': 'application/ofd', 'Content-Length': '999999999'}, 413),
                                  ({'Content-Type': 'application/ofd', 'Content-Length': 'bad'}, 400)]:
            with self.subTest(headers=headers), self.assertRaises(HTTPError) as error:
                self.request('inspect', data=b'bad', headers=headers)
            self.assertEqual(error.exception.code, expected)

    def test_shutdown_releases_server_loop(self):
        with self.request('shutdown', data=b'') as response:
            self.assertEqual(response.status, 200)
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def test_verification_endpoint_executes_m3_without_persisting_document(self):
        from examples.create_verified_demo import build_verified_demo
        data = build_verified_demo()
        with self.request('verify', data=data, headers={'Content-Type':'application/ofd'}) as response:
            report = json.load(response)
        self.assertEqual(report['m3_validation']['checked_status'], 'passed')
        self.assertEqual(report['m3_validation']['overall_status'], 'incomplete')
        self.assertEqual(self.server.document, self.document)

    def test_verification_rejects_bad_uid_foreign_origin_and_content_type(self):
        for headers, code in [({'Content-Type':'application/ofd','X-Sealverify-SM2-ID':'invalid'},400),
                              ({'Content-Type':'application/ofd','X-Sealverify-SM2-ID':''},400),
                              ({'Content-Type':'application/ofd','Origin':'https://example.com'},403),
                              ({'Content-Type':'text/plain'},415)]:
            with self.subTest(code=code), self.assertRaises(HTTPError) as error:
                self.request('verify',data=self.document,headers=headers)
            self.assertEqual(error.exception.code,code)


class DocumentInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / '中文 文件.OFD'

    def test_valid_case_insensitive_path(self):
        data = WEB_ROOT.joinpath('demo.ofd').read_bytes()
        self.path.write_bytes(data)
        self.assertEqual(read_document(self.path), data)

    def test_empty_and_non_zip_are_reported(self):
        for data in (b'', b'not a zip'):
            self.path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, '有效的 OFD'):
                read_document(self.path)

    def test_missing_root_is_reported(self):
        with ZipFile(self.path, 'w') as archive:
            archive.writestr('unrelated.xml', '<x/>')
        with self.assertRaisesRegex(ValueError, 'OFD.xml'):
            read_document(self.path)

    def test_size_limit_is_enforced_before_zip_parsing(self):
        self.path.write_bytes(b'12345')
        with patch('sealverify.reader.MAX_FILE_BYTES', 4):
            with self.assertRaisesRegex(ValueError, '超过'):
                read_document(self.path)

    def test_unknown_suffix_and_missing_file_are_reported(self):
        with self.assertRaisesRegex(ValueError, '.ofd'):
            read_document(self.path.with_suffix('.txt'))
        with self.assertRaises(FileNotFoundError):
            read_document(self.path)


if __name__ == '__main__':
    unittest.main()
