"""GB/T 38540—2020 格式诊断：逐项记录、继续独立检查，不执行密码验签。"""

import re
from collections import Counter

from asn1crypto import core, x509, cms, tsp

from ..results import CheckResult, CheckSpec, CheckStatus, VerificationReport
from .asn1 import Node, SM2_SM3, RSA_SIGNATURE_OIDS, Decoder


STANDARD = 'GB/T 38540—2020'
MAX_CHECKS = 512


class LimitError(ValueError):
    """实现限额不构成标准不符合的证据。"""


def frames(data):
    """浅层 DER 分帧；保留坏 TLV 之前的字段，不猜测损坏后的边界。"""
    offset, count = 0, 0
    while offset < len(data):
        count += 1
        if count > 20000:
            raise LimitError('ASN.1 单层节点超过 20000 个')
        start = offset
        if offset + 2 > len(data):
            raise ValueError('DER 标签/长度截断')
        tag, length = data[offset:offset + 2]
        offset += 2
        if tag & 31 == 31:
            raise LimitError('暂不支持 ASN.1 高编号标签')
        if length & 128:
            count = length & 127
            if count == 0:
                raise ValueError('DER 不允许不定长编码')
            if count > 4:
                raise LimitError('DER 长度超过实现限额')
            encoded = data[offset:offset + count]
            if len(encoded) != count:
                raise ValueError('DER 长度截断')
            length = int.from_bytes(encoded, 'big')
            if encoded[0] == 0 or length < 128:
                raise ValueError('DER 长度不是最短编码')
            offset += count
        end = offset + length
        if end > len(data):
            raise ValueError('DER 内容截断，后续字段边界无法确定')
        yield Node(tag, data[offset:end], data[start:end])
        offset = end


def primitive(node):
    """核对支持的 DER 基本编码；不是通用 ASN.1 或证书配置符合性认证。"""
    tag, value = node.tag, node.content
    if tag == 2:
        if not value or (len(value) > 1 and ((value[0] == 0 and value[1] < 128) or
                                           (value[0] == 255 and value[1] >= 128))):
            raise ValueError('INTEGER 为空或不是最短有符号编码')
    elif tag == 1:
        if value not in (b'\x00', b'\xff'):
            raise ValueError('DER BOOLEAN 必须编码为 00 或 ff')
    elif tag == 3:
        if not value or value[0] > 7 or (len(value) == 1 and value[0]) or (
                value[0] and value[-1] & ((1 << value[0]) - 1)):
            raise ValueError('BIT STRING 未使用位数或尾部填充不正确')
    elif tag == 5 and value:
        raise ValueError('NULL 必须为空')
    elif tag == 6:
        if not value or value[-1] & 128:
            raise ValueError('OID 为空或子标识截断')
        first = True
        for byte in value:
            if first and byte == 128:
                raise ValueError('OID 子标识不是最短编码')
            first = not (byte & 128)
    elif tag in (12, 19, 22, 23, 24):
        text = value.decode('utf-8' if tag == 12 else 'ascii')
        if tag == 19 and not re.fullmatch(r"[A-Za-z0-9 '()+,\-./:=?]*", text):
            raise ValueError('PrintableString 包含非法字符')
        if tag == 24:
            if not re.fullmatch(r'\d{14}(?:\.\d*[1-9])?Z', text):
                raise ValueError('DER GeneralizedTime 需要完整秒、UTC Z，且小数无尾随零')
            core.GeneralizedTime.load(node.raw, strict=True).native
        if tag == 23:
            if not re.fullmatch(r'\d{12}Z', text):
                raise ValueError('DER UTCTime 需要完整秒和 UTC Z')
            core.UTCTime.load(node.raw, strict=True).native


def der_tree(data):
    nodes = list(frames(data))
    if len(nodes) != 1 or nodes[0].tag != 48:
        raise ValueError('应为单一 DER SEQUENCE，不能有尾随内容')
    pending, count = [(nodes[0], 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 32 or count > 20000:
            raise LimitError('ASN.1 层级或节点超过检查限额')
        if node.tag & 32:
            children = list(frames(node.content))
            if node.tag == 49 and [n.raw for n in children] != sorted(n.raw for n in children):
                raise ValueError('DER SET 元素顺序不规范')
            pending.extend((n, depth + 1) for n in children)
        else:
            primitive(node)
    return nodes[0]


class FormatChecker:
    def __init__(self, location, object_id):
        self.location, self.object_id = location, object_id
        self.plan, self.results = [], []
        self.limited = False
        self.readable = set()
        self.omitted = Counter()

    def record(self, path, label, status, message, reference, expected=None, actual=None):
        if len(self.results) >= MAX_CHECKS:
            self.limited = True
            self.omitted[status] += 1
            return
        self.plan.append(CheckSpec(self.object_id, path, label))
        self.results.append(CheckResult(self.object_id, path, CheckStatus(status), message,
            location=self.location + '/' + path, expected=expected, actual=actual,
            standard_reference=STANDARD + ' ' + reference,
            remediation=None if status in ('passed', 'not_applicable') else
            '结合字段位置与标准复核；本项不阻断其他独立检查，不能据此认定签章有效。'))

    def run(self, path, label, reference, fn, *, dependency=True, expected=None, actual=None):
        if not dependency:
            self.record(path, label, 'skipped', '前置字段缺失、损坏或无法安全定位，未猜测内容。', reference, expected)
            return None
        try:
            result = fn()
        except LimitError as exc:
            self.record(path, label, 'indeterminate', str(exc), reference, expected)
        except (ValueError, TypeError, KeyError, IndexError, OverflowError) as exc:
            self.record(path, label, 'failed', str(exc)[:300], reference, expected, actual or str(exc)[:300])
        except Exception as exc:
            # 单个检查器的异常不应中断同一签章的其他检查；不输出可能含原文的异常详情。
            self.record(path, label, 'error', '检查器异常：' + type(exc).__name__, reference, expected)
        else:
            self.record(path, label, 'passed', '本项结构或编码检查通过，不代表密码验签通过。', reference, expected)
            return result
        return None

    def fields(self, node, path, names, reference, optional=()):
        found = []
        def read():
            if node.tag != 48:
                raise ValueError('预期 SEQUENCE，实际标签 0x%02x' % node.tag)
            for item in frames(node.content):
                if len(found) >= 256:
                    raise LimitError('单层字段超过 256 个')
                found.append(item)
            self.readable.add(path)
            if not len(names) - len(optional) <= len(found) <= len(names):
                raise ValueError('字段数为 %s，预期 %s–%s；按定义位置读取，不猜测错位字段' %
                                 (len(found), len(names) - len(optional), len(names)))
            return True
        self.run(path + '/structure', '结构、字段数与顺序', reference, read, dependency=node is not None,
                 expected='SEQUENCE: ' + ', '.join(names))
        result = {}
        for index, name in enumerate(names):
            result[name] = found[index] if index < len(found) else None
            if path in self.readable and index >= len(found) and name not in optional:
                self.record(path + '/' + name + '/presence', name + ' 必填项', 'failed',
                            '必填字段缺失或位于无法安全定位的区域。', reference, '必填字段存在')
        return result

    def value(self, node, path, cls, reference, nonempty=False):
        def read():
            if node.tag != cls.tag:
                raise ValueError('预期 %s，实际标签 0x%02x' % (cls.__name__, node.tag))
            primitive(node)
            if cls is core.Integer and len(node.content) > 8:
                raise LimitError('属性 INTEGER 超过 64 位实现范围')
            if cls in (core.IA5String, core.UTF8String, core.PrintableString) and len(node.content) > 4096:
                raise LimitError('文本超过 4096 字节检查上限')
            if cls is core.OctetBitString and node.content[0] != 0:
                raise ValueError('杂凑、签名和时间戳应为字节对齐 BIT STRING')
            value = cls.load(node.raw, strict=True).native
            if nonempty and not value:
                raise ValueError('字段值为空')
            return value
        return self.run(path, path.rsplit('/', 1)[-1] + ' 类型与编码', reference, read, dependency=node is not None,
                        expected=cls.__name__ + ('，非空' if nonempty else ''),
                        actual='标签 0x%02x，内容长度 %s 字节' % (node.tag, len(node.content)) if node is not None else None)

    def rule(self, path, label, reference, condition, expected, dependency=True, actual=None):
        def check():
            if not condition:
                raise ValueError('不符合约束：' + expected)
            return True
        return self.run(path, label, reference, check, dependency=dependency, expected=expected, actual=actual)

    def optional(self, node, path, reference, tagged=False, known=True):
        if node is None:
            self.record(path, '可选字段', 'not_applicable' if known else 'skipped',
                        '可选字段未提供。' if known else '前置结构不可读，无法确定可选字段是否存在。', reference)
            return None
        if not tagged:
            return node
        def unwrap():
            if node.tag != 160:
                raise ValueError('预期 [0] EXPLICIT 标签')
            items = list(frames(node.content))
            if len(items) != 1:
                raise ValueError('[0] EXPLICIT 必须包含一个完整字段')
            return items[0]
        return self.run(path + '/tag', '可选字段标签', reference, unwrap)

    def certificate(self, node, path, reference):
        data = self.value(node, path + '/octets', core.OctetString, reference, True)
        def read():
            if len(data) > 64 * 1024:
                raise LimitError('证书超过 64 KiB 检查上限')
            outer = der_tree(data)
            if len(list(frames(outer.content))) != 3:
                raise ValueError('Certificate 必须含三个字段')
            cert = x509.Certificate.load(data, strict=True)
            # 访问必要字段触发延迟解码；不使用证书主体的公钥去判断颁发者签名算法。
            tbs = cert['tbs_certificate']
            for name in ('serial_number', 'signature', 'issuer', 'validity', 'subject', 'subject_public_key_info'):
                if isinstance(tbs[name], core.Void):
                    raise ValueError('Certificate 缺少必要字段 ' + name)
            tbs['serial_number'].native
            tbs['issuer'].native
            tbs['subject'].native
            tbs['validity'].native
            tbs['signature']['algorithm'].dotted
            cert['signature_algorithm']['algorithm'].dotted
            cert['signature_value'].native
            return tbs['subject_public_key_info']['algorithm']
        return self.run(path + '/certificate', 'Certificate DER 容器及必要字段', reference,
                        read, dependency=data is not None, expected='可解码的 X.509 Certificate DER')

    def extensions(self, node, path, reference, tagged=False, known=True):
        node = self.optional(node, path, reference, tagged, known)
        if node is None:
            return
        def read():
            if node.tag != 48:
                raise ValueError('ExtensionDatas 应为 SEQUENCE OF')
            items = list(frames(node.content))
            if len(items) > 128:
                raise LimitError('扩展超过 128 项检查上限')
            return items
        items = self.run(path + '/list', '扩展列表', reference, read)
        for i, item in enumerate(items or []):
            loc = path + '/' + str(i)
            # critical 在中间且有 DEFAULT，不能将省略的 BOOLEAN 当成缺少字段。
            def parts():
                if item.tag != 48:
                    raise ValueError('ExtData 应为 SEQUENCE')
                values = list(frames(item.content))
                if len(values) not in (2, 3):
                    raise ValueError('ExtData 应有 2 或 3 个字段')
                return values
            values = self.run(loc + '/structure', 'ExtData 结构', reference, parts)
            if values is None:
                continue
            self.value(values[0], loc + '/extnID', core.ObjectIdentifier, reference)
            self.value(values[-1], loc + '/extnValue', core.OctetString, reference)
            if len(values) == 3:
                critical = self.value(values[1], loc + '/critical', core.Boolean, reference)
                self.rule(loc + '/default', 'DEFAULT 编码', reference, critical is True,
                          'DER 编码应省略 DEFAULT FALSE', critical is not None)
                if critical:
                    self.record(loc + '/meaning', '关键扩展语义', 'indeterminate',
                                '未实现该自定义关键扩展的语义，需要人工复核。', reference)

    def signature_bytes(self, node, algorithm, path, reference):
        data = self.value(node, path + '/bits', core.OctetBitString, reference, True)
        def decode():
            decoded = Decoder(lambda *args: None).signature_value(data, algorithm, path)['decoded']
            if decoded['status'] in ('unsupported', 'unavailable'):
                raise LimitError(decoded['message'])
            if decoded['status'] != 'decoded':
                raise ValueError(decoded['message'])
            return True
        self.run(path + '/encoding', '签名值编码（不验证数学关系）', reference, decode,
                 dependency=data is not None and algorithm is not None)

    def algorithm(self, node, key, path, reference):
        oid = self.value(node, path + '/oid', core.ObjectIdentifier, reference)
        def match():
            key_oid = key['algorithm'].dotted
            if oid == SM2_SM3:
                if key_oid == '1.2.156.10197.1.301':
                    return True
                if key_oid == '1.2.840.10045.2.1':
                    if key['parameters'].name != 'named':
                        raise LimitError('未支持显式曲线参数，无法判断是否为 SM2 曲线')
                    curve = core.ObjectIdentifier.load(key['parameters'].dump(), strict=True).dotted
                    if curve == '1.2.156.10197.1.301':
                        return True
                raise ValueError('SM2 签名算法与证书公钥算法/命名曲线声明不一致')
            if oid in RSA_SIGNATURE_OIDS:
                if key_oid not in ('1.2.840.113549.1.1.1', '1.2.840.113549.1.1.10'):
                    raise ValueError('RSA 签名算法与证书公钥算法声明不一致')
                if key_oid.endswith('.10') and not oid.endswith('.10'):
                    raise ValueError('仅限 PSS 的公钥不匹配 PKCS #1 v1.5 签名声明')
                return True
            raise LimitError('算法 OID 未在本工具的 SM2/RSA 声明检查范围内')
        self.run(path + '/key_match', '签名算法与签名者公钥声明', reference, match,
                 dependency=oid is not None and key is not None)
        return oid

    def seal(self, node, path):
        s = self.fields(node, path, ('eSealInfo', 'cert', 'signAlgID', 'signedValue'), '6.1.1')
        info = self.fields(s['eSealInfo'], path + '/eSealInfo', ('header', 'esID', 'property', 'picture', 'extDatas'), '6.1.2.1', ('extDatas',))
        hpath = path + '/header'
        h = self.fields(info['header'], hpath, ('ID', 'version', 'Vid'), '6.1.2.2')
        id_value = self.value(h['ID'], hpath + '/ID', core.IA5String, '6.1.2.2')
        ver = self.value(h['version'], hpath + '/version', core.Integer, '6.1.2.2')
        self.value(h['Vid'], hpath + '/Vid', core.IA5String, '6.1.2.2')
        self.rule(hpath + '/id_value', '印章头标识', '6.1.2.2', id_value == 'ES', 'ID = ES', id_value is not None, repr(id_value)[:128])
        self.rule(hpath + '/version_value', '印章版本', '6.1.2.2', ver == 4, 'version = 4', ver is not None, str(ver))
        self.value(info['esID'], path + '/esID', core.IA5String, '6.1.2.3')
        ppath = path + '/property'
        p = self.fields(info['property'], ppath, ('type', 'name', 'certListType', 'certList', 'createDate', 'validStart', 'validEnd'), '6.1.2.4')
        self.value(p['type'], ppath + '/type', core.Integer, '6.1.2.4')
        self.value(p['name'], ppath + '/name', core.UTF8String, '6.1.2.4')
        kind = self.value(p['certListType'], ppath + '/certListType', core.Integer, '6.1.2.4')
        self.rule(ppath + '/list_type', '证书列表类型', '6.1.2.4', kind in (1, 2), 'certListType = 1 或 2', kind is not None, str(kind))
        def entries():
            if p['certList'].tag != 48:
                raise ValueError('证书列表应为 SEQUENCE OF')
            items = list(frames(p['certList'].content))
            if not items:
                raise ValueError('证书或证书杂凑列表至少包含一项')
            if len(items) > 64:
                raise LimitError('授权证书列表超过 64 项检查上限')
            return items
        items = self.run(ppath + '/certList', '授权证书列表', '6.1.2.4', entries, dependency=p['certList'] is not None)
        for i, item in enumerate(items or []):
            loc = ppath + '/certList/' + str(i)
            if kind == 1:
                self.certificate(item, loc, '6.1.2.4')
            elif kind == 2:
                d = self.fields(item, loc, ('type', 'value'), '6.1.2.4')
                self.value(d['type'], loc + '/type', core.PrintableString, '6.1.2.4')
                self.value(d['value'], loc + '/value', core.OctetString, '6.1.2.4', True)
            else:
                self.record(loc, '授权列表条目', 'skipped', '列表类型不可用，未猜测 CHOICE 分支。', '6.1.2.4')
        for name in ('createDate', 'validStart', 'validEnd'):
            self.value(p[name], ppath + '/' + name, core.GeneralizedTime, '6.1.2.4')
        ipath = path + '/picture'
        pic = self.fields(info['picture'], ipath, ('type', 'data', 'width', 'height'), '6.1.2.5')
        for name, cls in [('type', core.IA5String), ('data', core.OctetString), ('width', core.Integer), ('height', core.Integer)]:
            self.value(pic[name], ipath + '/' + name, cls, '6.1.2.5')
        self.extensions(info['extDatas'], path + '/extDatas', '6.1.2.6', known=path + '/eSealInfo' in self.readable)
        key = self.certificate(s['cert'], path + '/cert', '6.1.3')
        oid = self.algorithm(s['signAlgID'], key, path + '/signAlgID', '6.1.4')
        self.signature_bytes(s['signedValue'], oid, path + '/signedValue', '6.1.5')
        return ver

    def signature(self, data):
        available = data is not None
        top = []
        def read():
            if len(data) > 16 * 1024 * 1024:
                raise LimitError('签章数据超过 16 MiB 检查上限')
            top.extend(frames(data))
            if len(top) != 1 or top[0].tag != 48:
                raise ValueError('SES_Signature 必须为单一 DER SEQUENCE，不能有尾随内容')
            return True
        self.run('container', '电子签章 DER 容器', '7.1.1、7.3 a)', read, dependency=available)
        node = top[0] if top and top[0].tag == 48 else None
        s = self.fields(node, 'signature', ('toSign', 'cert', 'signatureAlgID', 'signature', 'timeStamp'), '7.1.1', ('timeStamp',))
        t = self.fields(s['toSign'], 'toSign', ('version', 'eseal', 'timeInfo', 'dataHash', 'propertyInfo', 'extDatas'), '7.1.2', ('extDatas',))
        ver = self.value(t['version'], 'toSign/version', core.Integer, '7.1.2')
        try:
            seal_version = self.seal(t['eseal'], 'toSign/eseal')
        except Exception as exc:
            self.record('embedded_seal_error', '内嵌印章格式检查', 'error',
                        '检查器异常：' + type(exc).__name__ + '；签章其他字段继续检查。', '6.1、7.3 a)')
            seal_version = None
        self.rule('version_match', '签章与印章版本一致', '7.1.2、6.1.2.2', ver == seal_version == 4,
                  '签章版本 = 内嵌印章版本 = 4', ver is not None and seal_version is not None,
                  '签章版本 %s，内嵌印章版本 %s' % (ver, seal_version))
        self.value(t['timeInfo'], 'toSign/timeInfo', core.GeneralizedTime, '7.1.2')
        digest = self.value(t['dataHash'], 'toSign/dataHash', core.OctetBitString, '7.1.2', True)
        prop = self.value(t['propertyInfo'], 'toSign/propertyInfo', core.IA5String, '7.1.2', True)
        if prop is not None:
            self.record('property_scope', '原文属性中的保护范围', 'indeterminate',
                        'propertyInfo 由厂商定义；已核对编码，需人工确认其中至少包含签名保护范围。', '7.1.2')
        else:
            self.record('property_scope', '原文属性中的保护范围', 'skipped',
                        'propertyInfo 缺失、为空或不可读，无法复核其保护范围声明。', '7.1.2')
        self.extensions(t['extDatas'], 'toSign/extDatas', '7.1.2、6.1.2.6', True, 'toSign' in self.readable)
        key = self.certificate(s['cert'], 'cert', '7.1.3')
        oid = self.algorithm(s['signatureAlgID'], key, 'signatureAlgID', '7.1.4')
        if oid == SM2_SM3:
            self.rule('sm3_length', 'SM2 对应的原文杂凑长度', '7.1.5', digest is not None and len(digest) == 32,
                      'SM3 杂凑为 32 字节；未重算原文', digest is not None,
                      '%s 字节' % len(digest) if digest is not None else None)
        self.signature_bytes(s['signature'], oid, 'signatureValue', '7.1.5')
        stamp = self.optional(s['timeStamp'], 'timeStamp', '7.1.1、7.1.6', True, 'signature' in self.readable)
        if stamp is not None:
            raw = self.value(stamp, 'timeStamp/bits', core.OctetBitString, '7.1.6', True)
            def timestamp():
                der_tree(raw)
                token = cms.ContentInfo.load(raw, strict=True)
                if token['content_type'].native != 'signed_data':
                    raise ValueError('时间戳容器不是 CMS SignedData')
                signed = token['content']
                content = signed['encap_content_info']
                if content['content_type'].native != 'tst_info' or isinstance(content['content'], core.Void):
                    raise ValueError('时间戳缺少 TSTInfo')
                info = content['content'].parsed
                if not isinstance(info, tsp.TSTInfo):
                    raise ValueError('TSTInfo 无法解码')
                info.native
                if len(signed['signer_infos']) == 0:
                    raise ValueError('时间戳 SignedData 缺少签名者信息')
                return True
            self.run('timeStamp/container', '时间戳 DER/CMS/TSTInfo 容器', '7.1.6', timestamp, dependency=raw is not None)
        self.record('referenced_profiles', '引用标准及应用语义的完整符合性', 'indeterminate',
                    '本步检查可读结构；GB/T 20518、20520、33560、35276 的完整配置约束及图像/扩展业务语义尚未全部实现，需要复核。',
                    '6.1、7.1.3–7.1.6')

    def report(self):
        if self.limited:
            self.plan.append(CheckSpec(self.object_id, 'check_limit', '检查记录上限'))
            status = CheckStatus.FAILED if self.omitted['failed'] else CheckStatus.INDETERMINATE
            self.results.append(CheckResult(self.object_id, 'check_limit', status,
                '检查明细超过 %s 条，省略 %s 条（失败 %s、错误 %s）；独立检查仍继续，不能判为完整通过。' %
                (MAX_CHECKS, sum(self.omitted.values()), self.omitted['failed'], self.omitted['error'])))
        report = VerificationReport(self.location, tuple(self.plan), tuple(self.results)).to_dict()
        report.pop('generated_at')
        report.update(stage='signature_data_format', standard=STANDARD, continuation='collect_all',
                      cryptographic_verification='not_performed', omitted_checks=dict(self.omitted))
        return report


def check_signature_format(data, location='SignedValue', object_id='signature', unavailable=None):
    checker = FormatChecker(location, object_id)
    if data is None:
        checker.record('resource', '签章数据可读取性', 'indeterminate',
                       unavailable or '未获得签章数据，见包内资源解析问题。', '7.3 a)')
    try:
        checker.signature(data)
    except Exception as exc:
        checker.record('checker_error', '格式检查器', 'error',
                       '格式检查器异常：' + type(exc).__name__ + '；其他签章继续检查。', '7.3 a)')
    return checker.report()
