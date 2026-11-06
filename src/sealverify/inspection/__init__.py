"""有界、只读的 OFD 签章清单。解析状态与密码验证结论严格分离。"""

import base64
from collections import Counter
from io import BytesIO
import math
import posixpath
import zlib
from zipfile import BadZipFile, ZipFile

from defusedxml import ElementTree as ET

from .asn1 import Decoder, binary, root


NS = '{http://www.ofdspec.org/2016}'
MAX_FILE_BYTES = 256 * 1024 * 1024


def child(element, name):
    return element.find(NS + name) if element is not None else None


def children(element, name):
    return element.findall(NS + name) if element is not None else []


def text(element, name=None):
    if name is not None:
        element = child(element, name)
    value = (element.text or '').strip() if element is not None else ''
    if len(value) > 4096:
        raise ValueError('XML 文本超过 4096 字符上限')
    return value


def resolve(source, value):
    """OFD 的 / 表示包根目录；不访问文件系统或 URL。"""
    if not value or '\\' in value or ':' in value or '\x00' in value:
        raise ValueError('缺失或不安全的包内路径')
    path = posixpath.normpath(value.lstrip('/') if value.startswith('/') else posixpath.join(posixpath.dirname(source), value))
    if path == '..' or path.startswith('../') or path in ('', '.'):
        raise ValueError('路径超出 OFD 包根目录')
    return path


def rectangle(value):
    parts = [float(item) for item in value.split()]
    if len(parts) != 4 or not all(math.isfinite(item) for item in parts) or parts[2] <= 0 or parts[3] <= 0:
        raise ValueError('矩形需要四个有限数值，宽和高应大于零')
    return parts


class Inspection:
    def __init__(self, archive):
        self.archive = archive
        self.issues = []
        self.issue_count = 0
        self.counts = Counter(item.filename for item in archive.infolist())
        self.bytes_read = 0
        self.signature_count = 0
        self.decoder = Decoder(self.issue)

    def issue(self, code, location, message):
        self.issue_count += 1
        if len(self.issues) < 500:
            self.issues.append({'code': code, 'location': location, 'message': message[:1000]})
        elif len(self.issues) == 500:
            self.issues.append({'code': 'issue_limit', 'location': 'OFD.xml', 'message': '问题记录超过 500 条，后续记录已截断。'})

    def attempt(self, location, fn):
        try:
            return fn()
        except (ValueError, OSError, KeyError, RuntimeError, ET.ParseError, RecursionError, zlib.error) as exc:
            self.issue('parse_error', location, str(exc))
            return None

    def read(self, path, limit=16 * 1024 * 1024):
        if self.counts[path] != 1:
            raise ValueError('包内文件缺失或存在重名条目：' + path)
        info = self.archive.getinfo(path)
        if info.flag_bits & 1:
            raise ValueError('不支持加密 ZIP 条目')
        if info.file_size > limit or self.bytes_read + info.file_size > 128 * 1024 * 1024:
            raise ValueError('条目或累计解析读取量超限')
        self.bytes_read += info.file_size
        with self.archive.open(info) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('条目读取超限')
        return data

    def xml(self, path, expected):
        element = ET.fromstring(self.read(path, 2 * 1024 * 1024), forbid_dtd=True, forbid_entities=True, forbid_external=True)
        if element.tag != NS + expected:
            raise ValueError('不支持的 XML 命名空间或根元素，预期 ' + expected)
        pending, count = [(element, 0)], 0
        while pending:
            item, depth = pending.pop()
            count += 1
            if depth > 64 or count > 20000:
                raise ValueError('XML 层级或节点数量超限')
            if any(len(value) > 4096 for value in item.attrib.values()):
                raise ValueError('XML 属性过长')
            pending.extend((nested, depth + 1) for nested in item)
        return element

    def path(self, source, value, location):
        return self.attempt(location, lambda: resolve(source, value))

    def signature(self, entry, index_path, pages, key):
        start = len(self.issues)
        issue_start = self.issue_count
        signature = {'key': key, 'id': entry.get('ID'), 'type': entry.get('Type'),
                     'index_path': index_path, 'verification': 'not_performed',
                     'references': [], 'placements': []}
        if not signature['id']:
            self.issue('missing_field', index_path + '/Signature/@ID', '缺少签章标识。')
        source = self.path(index_path, entry.get('BaseLoc', ''), index_path + '/Signature/@BaseLoc')
        signature['source_path'] = source
        element = self.attempt(source or index_path, lambda: self.xml(source, 'Signature')) if source else None
        if element is not None:
            info = child(element, 'SignedInfo')
            if info is None:
                self.issue('missing_signed_info', source, '缺少 SignedInfo；仍继续读取 SignedValue。')
            provider = child(info, 'Provider')
            signature['provider'] = dict(provider.attrib) if provider is not None else None
            if provider is None:
                self.issue('missing_field', source + '/SignedInfo/Provider', '缺少签章组件提供者信息。')
            for name, key_name in [('SignatureMethod', 'algorithm'), ('SignatureDateTime', 'declared_time')]:
                value = self.attempt(source + '/SignedInfo/' + name, lambda n=name: text(info, n))
                signature[key_name] = value
            refs = child(info, 'References')
            signature['reference_method'] = refs.get('CheckMethod') if refs is not None else None
            reference_entries = children(refs, 'Reference')
            if not reference_entries:
                self.issue('missing_references', source + '/References', '没有可读取的引用清单，不能确定保护范围。')
            if len(reference_entries) > 1024:
                self.issue('reference_limit', source, '引用超过 1024 条，后续条目未解析。')
            for number, ref in enumerate(reference_entries[:1024]):
                location = source + '/References/' + str(number)
                declared = ref.get('FileRef', '')
                resolved = self.path(source, declared, location + '/@FileRef')
                check = self.attempt(location + '/CheckValue', lambda: text(ref, 'CheckValue'))
                def digest():
                    if not check:
                        raise ValueError('缺少 CheckValue')
                    return binary(base64.b64decode(''.join(check.split()), validate=True))
                decoded = self.attempt(location + '/CheckValue', digest)
                present = bool(resolved and self.counts[resolved] == 1)
                if resolved and not present:
                    self.issue('reference_missing', location, '引用目标缺失或重名：' + resolved)
                signature['references'].append({'declared_path': declared, 'path': resolved,
                    'present': present, 'check_value': check, 'digest': decoded, 'verification': 'not_performed'})
            page_map = {}
            for page in pages:
                page_map.setdefault(page['id'], []).append(page)
            for number, stamp in enumerate(children(info, 'StampAnnot')):
                location = source + '/StampAnnot/' + str(number)
                if not stamp.get('ID'):
                    self.issue('missing_field', location + '/@ID', '缺少签章外观标识。')
                matches = page_map.get(stamp.get('PageRef'), [])
                page = matches[0] if len(matches) == 1 else None
                if page is None:
                    self.issue('unknown_page', location + '/@PageRef', '签章页面不存在或 Page ID 重复。')
                boundary = self.attempt(location + '/@Boundary', lambda: rectangle(stamp.get('Boundary', '')))
                clip = self.attempt(location + '/@Clip', lambda: rectangle(stamp.get('Clip', ''))) if stamp.get('Clip') else None
                signature['placements'].append({'id': stamp.get('ID'), 'page_id': stamp.get('PageRef'),
                    'page_number': page['number'] if page else None, 'boundary_mm': boundary, 'clip_mm': clip,
                    'page_box_mm': page['physical_box_mm'] if page else None})
            def parse_resource(name, target, callback):
                value = self.attempt(source + '/' + name, lambda: text(target))
                path = self.path(source, value or '', source + '/' + name)
                signature[name + '_path'] = path
                if path:
                    signature[name] = self.attempt(path, lambda: callback(self.read(path), path))
            seal = child(child(info, 'Seal'), 'BaseLoc')
            if seal is not None:
                parse_resource('external_seal', seal, lambda data, loc: self.decoder.seal(root(data), loc))
            parse_resource('signed_value', child(element, 'SignedValue'), self.decoder.signature)
        signature['issues'] = self.issues[start:].copy()
        signature['parse_status'] = 'partial' if self.issue_count > issue_start else 'parsed'
        return signature

    def document(self, body, index):
        start = len(self.issues)
        issue_start = self.issue_count
        location = 'OFD.xml/DocBody/' + str(index)
        doc_root = self.attempt(location + '/DocRoot', lambda: text(body, 'DocRoot'))
        path = self.path('OFD.xml', doc_root or '', location)
        output = {'index': index,
                  'id': self.attempt(location + '/DocID', lambda: text(child(body, 'DocInfo'), 'DocID')),
                  'title': self.attempt(location + '/Title', lambda: text(child(body, 'DocInfo'), 'Title')),
                  'path': path, 'pages': [], 'signatures': []}
        doc = self.attempt(path or 'OFD.xml', lambda: self.xml(path, 'Document')) if path else None
        if doc is not None:
            area = child(child(doc, 'CommonData'), 'PageArea')
            default_text = self.attempt(path + '/CommonData/PageArea', lambda: text(area, 'PhysicalBox'))
            default_box = self.attempt(path + '/CommonData/PageArea', lambda: rectangle(default_text)) if default_text else None
            templates = {}
            for entry in children(child(doc, 'CommonData'), 'TemplatePage'):
                templates.setdefault(entry.get('ID'), []).append(entry)
            template_boxes = {}

            def template_box(template_id):
                if template_id not in template_boxes:
                    choices = templates.get(template_id, [])
                    if len(choices) != 1:
                        raise ValueError('页面模板不存在或模板 ID 重复')
                    template_path = resolve(path, choices[0].get('BaseLoc', ''))
                    template = self.xml(template_path, 'Page')
                    value = text(child(template, 'Area'), 'PhysicalBox')
                    template_boxes[template_id] = rectangle(value) if value else None
                return template_boxes[template_id]

            for number, entry in enumerate(children(child(doc, 'Pages'), 'Page'), 1):
                loc = path + '/Pages/' + str(number)
                page_path = self.path(path, entry.get('BaseLoc', ''), loc)
                page = self.attempt(page_path, lambda: self.xml(page_path, 'Page')) if page_path else None
                own_box = self.attempt(loc + '/PhysicalBox', lambda: text(child(page, 'Area'), 'PhysicalBox'))
                box = self.attempt(loc + '/PhysicalBox', lambda: rectangle(own_box)) if own_box else None
                if box is None:
                    for template in children(page, 'Template'):
                        box = self.attempt(loc + '/Template', lambda: template_box(template.get('TemplateID')))
                        if box is not None:
                            break
                if box is None:
                    box = default_box
                if box is None:
                    self.issue('missing_page_box', loc, '页面、模板及公共数据均无可读的物理边界，不能准确高亮。')
                output['pages'].append({'id': entry.get('ID'), 'number': number, 'path': page_path, 'physical_box_mm': box})
            ids = Counter(page['id'] for page in output['pages'])
            if any(count > 1 for count in ids.values()):
                self.issue('duplicate_page_id', path, '页面 ID 重复，相应签章不能唯一定位。')
            if not output['pages']:
                self.issue('missing_pages', path, '没有可读取的页面清单。')
        indexes = []
        # DocBody 是标准入口；兼容 Document 内的同名扩展，路径归一化后去重。
        for source, owner in [('OFD.xml', body), (path, doc)]:
            if owner is None:
                continue
            for pointer in children(owner, 'Signatures'):
                pointer_text = self.attempt(source + '/Signatures', lambda: text(pointer))
                signature_path = self.path(source, pointer_text or '', source + '/Signatures')
                if signature_path and signature_path not in indexes:
                    indexes.append(signature_path)
        seen = set()
        for index_path in indexes:
            sigs = self.attempt(index_path, lambda: self.xml(index_path, 'Signatures'))
            if sigs is None:
                continue
            for number, entry in enumerate(children(sigs, 'Signature')):
                if self.signature_count >= 128:
                    self.issue('signature_limit', index_path, '全包签章超过 128 个，后续签章未解析。')
                    break
                self.signature_count += 1
                if entry.get('ID') in seen:
                    self.issue('duplicate_signature_id', index_path, '签章 ID 重复；用文档和清单序号分别标识。')
                seen.add(entry.get('ID'))
                output['signatures'].append(self.signature(entry, index_path, output['pages'],
                                                          '%s:%s:%s' % (index, len(output['signatures']), number)))
        output['issues'] = self.issues[start:].copy()
        output['parse_status'] = 'partial' if self.issue_count > issue_start else 'parsed'
        return output


def inspect_ofd(data: bytes) -> dict:
    """返回只读结构清单；任何解析状态都不代表验签通过。"""
    output = {'schema_version': 1, 'verification': 'not_performed', 'documents': [], 'issues': []}
    if len(data) > MAX_FILE_BYTES:
        output['issues'].append({'code': 'container_error', 'location': 'OFD', 'message': '文件超过 256 MiB 上限。'})
        output['parse_status'] = 'error'
        return output
    output['source'] = binary(data)
    try:
        with ZipFile(BytesIO(data)) as archive:
            if len(archive.infolist()) > 20000 or sum(item.file_size for item in archive.infolist()) > 512 * 1024 * 1024:
                raise ValueError('容器条目数量或声明解压大小超限')
            parser = Inspection(archive)
            for name, count in parser.counts.items():
                if count > 1:
                    parser.issue('duplicate_entry', name, 'ZIP 中存在重名条目；不会任选一个进行解析。')
            ofd = parser.attempt('OFD.xml', lambda: parser.xml('OFD.xml', 'OFD'))
            if ofd is not None:
                bodies = children(ofd, 'DocBody')
                if not bodies:
                    parser.issue('missing_document', 'OFD.xml', '没有 DocBody。')
                if len(bodies) > 32:
                    parser.issue('document_limit', 'OFD.xml', '文档超过 32 份，后续文档未解析。')
                for index, body in enumerate(bodies[:32]):
                    doc = parser.attempt('OFD.xml/DocBody/' + str(index), lambda: parser.document(body, index))
                    if doc is not None:
                        output['documents'].append(doc)
            output['issues'] = parser.issues
    except (BadZipFile, ValueError, OSError) as exc:
        output['issues'].append({'code': 'container_error', 'location': 'OFD', 'message': str(exc)[:1000]})
    output['parse_status'] = 'error' if not output['documents'] else ('partial' if output['issues'] else 'parsed')
    return output
