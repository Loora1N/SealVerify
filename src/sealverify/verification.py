"""M3：原始字节验签和杂凑诊断；无证书信任或可信时间的整体通过结论。"""

import base64
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from zipfile import ZipFile, BadZipFile

from asn1crypto import core

from .crypto import DEFAULT_SM2_ID, certificate, digest, hash_name, signature_hash, verify_signature
from .inspection import Inspection, inspect_ofd, resolve, child, children, text, NS
from .inspection.asn1 import octets, scalar, sequence
from .inspection.format import FormatChecker, LimitError, frames, der_tree


MAX_VERIFY_READ_BYTES = 128 * 1024 * 1024


class VerificationReader(Inspection):
    def read(self, path, limit=16 * 1024 * 1024):
        if self.counts[path] == 1:
            info = self.archive.getinfo(path)
            if info.file_size > limit or self.bytes_read + info.file_size > MAX_VERIFY_READ_BYTES:
                raise LimitError('资源大小或累计验证读取量超过实现限额，不能据此断言文件无效')
        return super().read(path, limit)


class Checks(FormatChecker):
    def record(self, path, label, status, message, reference, expected=None, actual=None):
        if status == 'passed':
            message = '本项检查通过；数学/字节一致性不代表证书可信或完整签章有效。'
        super().record(path, label, status, message, reference, expected, actual)

    def require(self, condition, message):
        if not condition:
            raise ValueError(message)
        return True

    def stage(self, path, fn):
        """隔离编排异常，保留已记录项并继续同一签章的独立阶段。"""
        try:
            return fn()
        except Exception as exc:
            self.record(path, '检查阶段异常', 'error',
                        '检查器异常：' + type(exc).__name__ + '；其他独立阶段继续。', '6.3、7.3')
            return None

    def finish(self, settings):
        # 沿用有界明细与省略计数；不混入格式阶段的通用覆盖文案。
        result = super().report('m3_verification')
        result.update(cryptographic_verification='attempted', settings=settings)
        result['coverage'] = {'complete': False, 'limitations': [
            '已执行支持范围内的密码运算与原始字节杂凑检查；未知算法/参数/保护范围不能按成功处理。',
            'M4 尚未完成：证书路径、吊销、证书有效期/用途、可信签章时间、时间戳与印章历史状态。',
            '未引用的包内内容不属于本次已核对的 References 范围；不以渲染页面推断整包保护。']}
        return result

    def node(self, data, path):
        prefix = []
        def read():
            if len(data) > 16 * 1024 * 1024:
                raise LimitError('ASN.1 输入超过 16 MiB 上限')
            prefix.extend(frames(data))
            return self.require(len(prefix) == 1 and prefix[0].tag == 48, '需要单一 DER SEQUENCE')
        self.run(path + '/container', '密码验证输入容器', '6.1、7.1', read, dependency=data is not None)
        return prefix[0] if prefix and prefix[0].tag == 48 else None


def seal_checks(c, node, role, sm2_id, at):
    path = 'seal/' + role
    fields = c.fields(node, path, ('info', 'cert', 'algorithm', 'signature'), '6.1.1')
    cert = c.value(fields['cert'], path + '/cert', core.OctetString, '6.1.3', True)
    oid = c.value(fields['algorithm'], path + '/algorithm', core.ObjectIdentifier, '6.1.4')
    sig = c.value(fields['signature'], path + '/signature', core.OctetBitString, '6.1.5', True)
    info = fields['info']
    c.run(path + '/signature_value', '制章签名数学验证（' + role + '）', '6.3 b)',
          lambda: verify_signature(cert, oid, info.raw, sig, sm2_id),
          dependency=all(v is not None for v in (cert, oid, info, sig)))
    parts = c.fields(info, path + '/info', ('header', 'id', 'property', 'picture', 'extensions'), '6.1.2.1', ('extensions',))
    props = c.fields(parts['property'], path + '/property', ('type', 'name', 'kind', 'certs', 'created', 'start', 'end'), '6.1.2.4')
    start = c.value(props['start'], path + '/valid_start', core.GeneralizedTime, '6.1.2.4')
    end = c.value(props['end'], path + '/valid_end', core.GeneralizedTime, '6.1.2.4')
    c.run(path + '/period', '本次验证时刻的印章有效期（不判断历史签章）', '6.3 d)',
          lambda: c.require(start <= at <= end, '本次验证时刻不在印章声明有效期内'),
          dependency=start is not None and end is not None,
          expected='%s 至 %s' % (start, end), actual=at.isoformat())
    return props


def authorization(c, props, cert):
    if props is None:
        c.run('authorization', '签章者与电子印章授权匹配', '7.3 c)', lambda: None, dependency=False)
        return
    kind = c.value(props['kind'], 'authorization/type', core.Integer, '7.3 c)')
    entries = []
    def read():
        node = props['certs']
        if node.tag != 48:
            raise ValueError('授权列表不是 SEQUENCE')
        for item in frames(node.content):
            if len(entries) >= 64:
                raise LimitError('授权列表超过 64 项上限')
            entries.append(item)
        return c.require(bool(entries), '授权列表为空')
    listed = c.run('authorization/list', '授权列表可读取性', '7.3 c)', read, dependency=props['certs'] is not None)
    match, unknown = False, listed is None
    for i, item in enumerate(entries):
        def compare():
            if kind == 1:
                member = octets(item)
                certificate(member)
                return member == cert
            if kind == 2:
                parts = sequence(der_tree(item.raw), 2, 2)
                name = hash_name(scalar(parts[0], core.PrintableString))
                return digest(cert, name) == octets(parts[1])
            raise LimitError('授权列表类型未知，无法匹配 CHOICE')
        result = c.run('authorization/member/' + str(i), '授权条目可比对性', '7.3 c)', compare,
                       dependency=cert is not None)
        match |= result is True
        unknown |= result is None
    def conclude():
        if match:
            return True
        if unknown:
            raise LimitError('可读授权条目未匹配，其他条目不可判断，不能断言不在完整列表中')
        return c.require(False, '签章者证书或其杂凑不在印章授权列表内')
    c.run('authorization', '签章者与电子印章授权匹配', '7.3 c)', conclude,
          dependency=cert is not None and kind is not None)


def references(c, reader, sig, signature_valid, xml_hash_valid, oid):
    xml = c.run('references/xml', '原始签章 XML 可读取性', '7.3 g)；OFD References',
                lambda: reader.xml(sig['source_path'], 'Signature'), dependency=bool(sig['source_path']))
    info = child(xml, 'SignedInfo')
    refs = child(info, 'References')
    entries = children(refs, 'Reference')
    c.run('references/selection', '签章描述与引用清单无歧义', '7.3 g)；OFD SignedInfo',
          lambda: c.require(len(children(xml, 'SignedInfo')) == 1 and
                            len(children(info, 'References')) == 1 and len(children(xml, 'SignedValue')) == 1,
                            'SignedInfo、References 或 SignedValue 缺失或重复，不能唯一选择'), dependency=xml is not None)
    declared = children(info, 'SignatureMethod')
    def method():
        c.require(len(declared) == 1, 'SignatureMethod 重复')
        if text(declared[0]) != oid:
            raise LimitError('XML SignatureMethod 与签章 OID 不一致或使用未支持的别名，需复核算法声明')
        return True
    if info is not None and not declared:
        c.record('references/signature_method', 'XML 与签章算法声明一致性', 'not_applicable',
                 '可选 XML 算法声明未提供，使用签章 DER 中的算法 OID。', '7.3 b)；OFD SignatureMethod')
    else:
        c.run('references/signature_method', 'XML 与签章算法声明一致性', '7.3 b)；OFD SignatureMethod',
              method, dependency=info is not None and oid is not None)
    def profile():
        if set(refs.attrib) != {'CheckMethod'}:
            raise LimitError('References 含未知属性或缺少 CheckMethod，不能确认引用处理语义')
        return True
    profile_known = c.run('references/profile', '引用清单处理配置', '7.3 g)；OFD References',
                          profile, dependency=refs is not None)
    def listing():
        c.require(refs is not None and entries and len(refs) == len(entries), '引用清单缺失、为空或含未知节点')
        if len(entries) > 1024:
            raise LimitError('引用超过 1024 项，仅核对可处理的前 1024 项')
        return True
    c.run('references/list', '引用清单存在且可完整处理', '7.3 g)；OFD References',
          listing, dependency=xml is not None)
    name = c.run('references/algorithm', '引用杂凑算法', '7.3 g)；OFD CheckMethod',
                 lambda: hash_name(refs.get('CheckMethod')), dependency=refs is not None)
    protected, seen = [], set()
    for index, ref in enumerate(entries[:1024]):
        loc = 'references/' + str(index)
        target = c.run(loc + '/path', '引用资源定位', '7.3 g)；OFD FileRef',
                       lambda: resolve(sig['source_path'], ref.get('FileRef', '')))
        if target:
            protected.append(target)
        def compare():
            if target in seen:
                raise ValueError('重复引用路径，未当成额外保护范围')
            seen.add(target)
            if set(ref.attrib) != {'FileRef'} or len(ref) != 1 or ref[0].tag != NS + 'CheckValue':
                raise LimitError('引用含未知属性、转换或节点，未猜测待杂凑字节')
            expected = base64.b64decode(''.join(text(ref, 'CheckValue').split()), validate=True)
            actual = digest(reader.read(target, 64 * 1024 * 1024), name)
            return c.require(expected == actual, '引用资源原始字节的杂凑与 CheckValue 不一致')
        c.run(loc + '/digest', '引用原始字节杂凑：' + (target or '不可定位'), '7.3 g)；OFD References',
              compare, dependency=target is not None and name is not None and profile_known is not None)
    c.run('references/binding', '引用清单与签章的密码绑定', '7.3 b)、g)',
          lambda: c.require(signature_valid and xml_hash_valid, '引用清单尚未通过签章及 Signature.xml 杂凑绑定'),
          dependency=signature_valid is not None and xml_hash_valid is not None)
    return protected


def verify_one(reader, sig, sm2_id, at, c, time_source):
    raw = c.run('signed_value/resource', '签章原始数据读取', '7.3 b)',
                lambda: reader.read(sig['signed_value_path']), dependency=bool(sig.get('signed_value_path')))
    s = c.fields(c.node(raw, 'signature'), 'signature', ('tbs', 'cert', 'oid', 'signature', 'timestamp'), '7.1.1', ('timestamp',))
    t = c.fields(s['tbs'], 'tbs', ('version', 'seal', 'time', 'hash', 'property', 'extensions'), '7.1.2', ('extensions',))
    cert = c.value(s['cert'], 'signer/cert', core.OctetString, '7.1.3', True)
    cert = c.run('signer/certificate', '签章者证书容器', '7.1.3', lambda: (certificate(cert), cert)[1], dependency=cert is not None)
    oid = c.value(s['oid'], 'signer/algorithm', core.ObjectIdentifier, '7.1.4')
    signature = c.value(s['signature'], 'signer/signature', core.OctetBitString, '7.1.5', True)
    valid = c.run('signature_value', '电子签章签名数学验证', '7.3 b)',
                  lambda: verify_signature(cert, oid, s['tbs'].raw, signature, sm2_id),
                  dependency=all(v is not None for v in (cert, oid, s['tbs'], signature)))
    props = c.stage('seal/embedded/checker', lambda: seal_checks(c, t['seal'], 'embedded', sm2_id, at))
    c.stage('authorization/checker', lambda: authorization(c, props, cert))
    external = None
    absent = sig['seal_format_validation']['external']['applicability'] == 'absent'
    if absent:
        c.record('seal/external', '外置印章', 'not_applicable', '未声明外置印章。', '6.3')
    else:
        external = c.run('seal/external/resource', '外置印章原始资源', '6.3',
                         lambda: reader.read(sig['external_seal_path']), dependency=bool(sig.get('external_seal_path')))
        c.stage('seal/external/checker', lambda: seal_checks(c, c.node(external, 'external'), 'external', sm2_id, at))
        c.run('seal_match', '内嵌与外置印章原始 DER 一致性', '7.3 a)；OFD Seal',
              lambda: c.require(external == t['seal'].raw, '外置印章与签章内嵌印章不一致'),
              dependency=external is not None and t['seal'] is not None)
    prop = c.value(t['property'], 'protected_scope/value', core.IA5String, '7.1.2', True)
    def scope():
        # 已支持的 OFD profile：明确指向本签章 Signature.xml 的包根绝对路径。
        if not prop.startswith('/'):
            raise LimitError('propertyInfo 不是已支持的 OFD 包根绝对路径，厂商语义需复核')
        target = resolve(sig['source_path'], prop)
        if target != sig['source_path']:
            raise LimitError('propertyInfo 指向其他资源，超出已支持的 OFD 保护范围配置，未绑定当前引用清单')
        return target
    target = c.run('protected_scope', '签名保护范围定位', '7.1.2、7.3 g)', scope, dependency=prop is not None)
    expected = c.value(t['hash'], 'document/hash', core.OctetBitString, '7.1.2', True)
    name = c.run('document/algorithm', '原文杂凑与签名算法协调', '7.1.5', lambda: signature_hash(oid), dependency=oid is not None)
    bound = c.run('document_digest', 'Signature.xml 原始字节杂凑', '7.3 g)',
                  lambda: c.require(digest(reader.read(target, 2 * 1024 * 1024), name) == expected,
                                    'Signature.xml 原始字节的杂凑与已签 dataHash 不一致'),
                  dependency=all(v is not None for v in (target, name, expected)))
    protected = c.stage('references/checker', lambda: references(c, reader, sig, valid, bound, oid))
    def format_status():
        reports = [sig['format_validation']] + list(sig['seal_format_validation'].values())
        if any(r['overall_status'] == 'failed' for r in reports):
            raise ValueError('前两步存在格式失败，密码运算的独立结果不能覆盖格式错误')
        unresolved = [check for r in reports for check in r['checks']
                      if check['status'] not in ('passed', 'not_applicable') and check['check_id'] != 'property_scope']
        if unresolved:
            raise LimitError('前两步存在未解决的字段/算法/资源问题，详见格式结果')
        return True
    c.run('format_dependency', '已执行格式检查的关联结果', '6.3 a)、7.3 a)', format_status)
    result = c.finish({'sm2_id_hex': sm2_id.hex(), 'verification_time': at.isoformat(), 'time_source': time_source})
    result['protected_files'] = protected
    return result


def verify_ofd(data, *, sm2_id=DEFAULT_SM2_ID, at=None):
    if not isinstance(sm2_id, bytes) or not 1 <= len(sm2_id) <= 8191:
        raise ValueError('SM2 用户标识需要 1–8191 字节')
    time_source = 'caller' if at is not None else 'local_clock'
    at = at or datetime.now(timezone.utc)
    if at.utcoffset() is None:
        raise ValueError('验证时刻必须包含时区')
    output = inspect_ofd(data)
    reports = []
    try:
        with ZipFile(BytesIO(data)) as archive:
            reader = VerificationReader(archive)
            for doc in output['documents']:
                for sig in doc['signatures']:
                    c = Checks(sig['source_path'] or sig['index_path'], sig['key'])
                    try:
                        result = verify_one(reader, sig, sm2_id, at, c, time_source)
                    except Exception as exc:
                        c.record('checker_error', 'M3 检查器', 'error',
                                 '检查器异常：' + type(exc).__name__ + '；后续签章继续。', '6.3、7.3')
                        result = c.finish({'sm2_id_hex': sm2_id.hex(), 'verification_time': at.isoformat(), 'time_source': time_source})
                    sig['m3_validation'] = result
                    reports.append(result)
    except (BadZipFile, ValueError, OSError):
        pass  # inspect_ofd 已报告容器问题；无结果不得成为通过。
    counts = Counter(r['checked_status'] for r in reports)
    checked = 'failed' if counts['failed'] else 'passed' if reports and not output['issues'] and counts['passed'] == len(reports) else 'incomplete'
    output['m3_validation'] = {'stage': 'm3_verification', 'checked_status': checked,
        'overall_status': 'failed' if checked == 'failed' else 'incomplete', 'signatures_checked': len(reports),
        'by_status': dict(counts), 'continuation': 'collect_all', 'cryptographic_verification': 'attempted',
        'message': '数学验签和引用杂凑按已支持范围执行；证书信任、吊销及可信时间仍未完成。'}
    # 原始属性的 verification=not_performed 保持为属性契约；实际运算只在 m3_validation 中表达。
    return output
