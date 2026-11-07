"""GB/T 38540—2020 第 6.1、7.1 节的只读结构解析，不执行密码验证。"""

import base64
from dataclasses import dataclass
import hashlib
from typing import Callable

from asn1crypto import core, x509, cms, tsp


SM2_SM3 = '1.2.156.10197.1.501'
# RFC 8017 A.2.3 / A.2.4：按签名算法 OID 分派，不用证书主体公钥算法猜测。
RSA_SIGNATURE_OIDS = {'1.2.840.113549.1.1.' + str(i) for i in (2, 4, 5, 10, 11, 12, 13, 14, 15, 16)}
MAX_SIGNATURE_BYTES = 64 * 1024


def binary(data: bytes) -> dict:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "hex_preview": data[:64].hex(), "truncated": len(data) > 64}


@dataclass
class Node:
    tag: int
    content: bytes
    raw: bytes

    def children(self):
        if not self.tag & 32:
            raise ValueError("应为 ASN.1 构造类型")
        return split(self.content)


def split(data: bytes):
    """有界 DER TLV 分帧；字段解码独立进行，坏字段不抹除相邻字段。"""
    result, offset = [], 0
    while offset < len(data):
        start = offset
        if len(result) >= 20000 or offset + 2 > len(data):
            raise ValueError("ASN.1 字段过多或截断")
        tag, size = data[offset], data[offset + 1]
        offset += 2
        if tag & 31 == 31:
            raise ValueError("暂不支持高编号 ASN.1 标签")
        if size & 128:
            count = size & 127
            if not count or count > 4 or offset + count > len(data):
                raise ValueError("不是有界 DER 长度")
            encoded = data[offset:offset + count]
            size = int.from_bytes(encoded, "big")
            if encoded[0] == 0 or size < 128:
                raise ValueError("非最短 DER 长度编码")
            offset += count
        end = offset + size
        if end > len(data):
            raise ValueError("ASN.1 内容截断")
        result.append(Node(tag, data[offset:end], data[start:end]))
        offset = end
    return result


def root(data: bytes) -> Node:
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("ASN.1 超过 16 MiB 解析上限")
    nodes = split(data)
    if len(nodes) != 1 or nodes[0].tag != 48:
        raise ValueError("应为单一 DER SEQUENCE")
    pending, count = [(nodes[0], 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 32 or count > 20000:
            raise ValueError("ASN.1 嵌套或节点数量超限")
        if node.tag & 32:
            pending.extend((child, depth + 1) for child in node.children())
    return nodes[0]


def scalar(node, cls):
    if node.tag != cls.tag:
        raise ValueError("字段 ASN.1 类型不匹配（预期 %s）" % cls.__name__)
    value = cls.load(node.raw, strict=True).native
    if isinstance(value, str) and len(value) > 4096:
        raise ValueError("文本超过 4096 字符展示上限")
    return value


def octets(node):
    return scalar(node, core.OctetString)


def bits(node):
    if node.tag != 3 or not node.content or node.content[0] != 0:
        raise ValueError("应为字节对齐的 BIT STRING")
    return node.content[1:]


def sequence(node, minimum, maximum):
    if node.tag != 48:
        raise ValueError("应为 SEQUENCE")
    children = node.children()
    if not minimum <= len(children) <= maximum:
        raise ValueError("SEQUENCE 字段数量不符合已支持结构")
    return children


class Decoder:
    def __init__(self, issue: Callable):
        self.issue = issue

    def field(self, location, fn):
        try:
            return fn()
        except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError) as exc:
            self.issue("asn1_field", location, str(exc))
            return None

    def signature_value(self, data, algorithm, location):
        """保留 v1 摘要契约供回归；界面仅使用新增 decoded 的完整签名内容。"""
        result = binary(data)
        decoded = {'algorithm_oid': algorithm, 'algorithm': 'SM2' if algorithm == SM2_SM3 else
                   ('RSA' if algorithm in RSA_SIGNATURE_OIDS else '未知算法'),
                   'status': 'decoded', 'verification': 'not_performed'}
        result['decoded'] = decoded
        if len(data) > MAX_SIGNATURE_BYTES:
            decoded.update(status='unavailable', message='签名值超过 64 KiB 展示上限，未展示；未截断为预览。')
            self.issue('signature_size_limit', location, decoded['message'])
            return result
        if not data:
            decoded.update(status='error', message='签名值为空。')
            self.issue('signature_encoding', location, decoded['message'])
            return result
        if algorithm == SM2_SM3:
            try:
                pair = sequence(root(data), 2, 2)
                values = []
                for name, node in zip(('r', 's'), pair):
                    raw = node.content
                    if node.tag != 2 or not raw or raw[0] & 128:
                        raise ValueError(name + ' 必须是非负 ASN.1 INTEGER')
                    if len(raw) > 1 and raw[0] == 0 and not raw[1] & 128:
                        raise ValueError(name + ' 包含多余的 INTEGER 前导零')
                    # DER 正号补零不属于数值，显示为完整的 32 字节大端无符号整数。
                    value = raw[1:] if len(raw) > 1 and raw[0] == 0 else raw
                    if len(value) > 32:
                        raise ValueError(name + ' 超过 256 位，无法按 SM2 曲线参数展示')
                    values.append(value.rjust(32, b'\x00').hex())
                decoded.update(encoding='ASN.1 DER SEQUENCE { r INTEGER, s INTEGER }',
                               r_hex=values[0], s_hex=values[1])
            except (ValueError, TypeError) as exc:
                decoded.update(status='error', message='SM2 签名值不能按 DER 拆分：' + str(exc),
                               signature_hex=data.hex())
                self.issue('signature_encoding', location, decoded['message'])
        else:
            # RSA 是签名字节串；即使恰好以 30 开头，也不能把它当 DER 解码。
            decoded.update(encoding='原始签名字节串', signature_hex=data.hex())
            if algorithm not in RSA_SIGNATURE_OIDS:
                decoded.update(status='unsupported', message='尚不支持按此签名算法拆分，显示完整原始字节。')
                self.issue('signature_algorithm_unsupported', location, decoded['message'])
        return result

    def certificate(self, data, location):
        result = {"data": binary(data), "verification": "not_performed"}
        def read():
            if len(data) > 64 * 1024:
                raise ValueError('证书超过 64 KiB 解析上限')
            root(data)
            return x509.Certificate.load(data, strict=True)
        cert = self.field(location, read)
        if cert is None:
            return result
        getters = {
            "subject": lambda: cert.subject.human_friendly,
            "issuer": lambda: cert.issuer.human_friendly,
            "serial_hex": lambda: format(cert.serial_number, "x"),
            "not_before": lambda: cert['tbs_certificate']['validity']['not_before'].native.isoformat(),
            "not_after": lambda: cert['tbs_certificate']['validity']['not_after'].native.isoformat(),
            "signature_algorithm": lambda: cert['signature_algorithm']['algorithm'].dotted,
            "public_key_algorithm": lambda: cert['tbs_certificate']['subject_public_key_info']['algorithm']['algorithm'].dotted,
            "key_usage": lambda: sorted(cert.key_usage_value.native) if cert.key_usage_value else None,
            "basic_constraints": lambda: cert.basic_constraints_value.native if cert.basic_constraints_value else None,
        }
        for key, getter in getters.items():
            result[key] = self.field(location + "/" + key, getter)
        result['certificate_signature'] = self.field(location + '/signatureValue', lambda:
            self.signature_value(bits(sequence(root(data), 3, 3)[2]), result['signature_algorithm'],
                                 location + '/signatureValue'))
        return result

    def extensions(self, node, location, tagged=False):
        if tagged:
            if node.tag != 160 or len(node.children()) != 1:
                raise ValueError("扩展应为 [0] EXPLICIT")
            node = node.children()[0]
        entries = sequence(node, 0, 128)
        output = []
        for index, entry in enumerate(entries):
            loc = location + "/" + str(index)
            fields = self.field(loc, lambda: sequence(entry, 2, 3))
            if fields is None:
                continue
            output.append({
                "oid": self.field(loc + "/oid", lambda: scalar(fields[0], core.ObjectIdentifier)),
                "critical": self.field(loc + "/critical", lambda: scalar(fields[1], core.Boolean)) if len(fields) == 3 else False,
                "value": self.field(loc + "/value", lambda: binary(octets(fields[-1]))),
            })
        return output

    def picture(self, node, location):
        fields = sequence(node, 4, 4)
        output = {"type": self.field(location + "/type", lambda: scalar(fields[0], core.IA5String)),
                  "width_mm": self.field(location + "/width", lambda: scalar(fields[2], core.Integer)),
                  "height_mm": self.field(location + "/height", lambda: scalar(fields[3], core.Integer))}
        data = self.field(location + "/data", lambda: octets(fields[1]))
        if data is not None:
            output["data"] = binary(data)
            mime = None
            if data.startswith(b'\x89PNG\r\n\x1a\n'):
                mime = 'image/png'
            elif data.startswith(b'\xff\xd8\xff'):
                mime = 'image/jpeg'
            elif data.startswith((b'GIF87a', b'GIF89a')):
                mime = 'image/gif'
            if mime and len(data) <= 1024 * 1024:
                output["preview"] = "data:" + mime + ";base64," + base64.b64encode(data).decode('ascii')
            else:
                self.issue("image_preview_unavailable", location, "图像不是受支持的位图或超过 1 MiB；保留数据摘要，不加载 SVG 等活动内容。")
        return output

    def property(self, node, location):
        fields = sequence(node, 7, 7)
        output = {}
        for index, key, cls in [(0, "type", core.Integer), (1, "name", core.UTF8String),
                                (2, "cert_list_type", core.Integer)]:
            output[key] = self.field(location + "/" + key, lambda i=index, c=cls: scalar(fields[i], c))
        for index, key in [(4, 'created'), (5, 'valid_start'), (6, 'valid_end')]:
            output[key] = self.field(location + "/" + key, lambda i=index: scalar(fields[i], core.GeneralizedTime).isoformat())
        entries = self.field(location + "/cert_list", lambda: sequence(fields[3], 0, 64))
        output['certificates'], output['certificate_digests'] = [], []
        if entries is not None:
            for index, entry in enumerate(entries):
                loc = location + "/cert_list/" + str(index)
                if output['cert_list_type'] == 1:
                    value = self.field(loc, lambda: self.certificate(octets(entry), loc))
                    output['certificates'].append(value)
                elif output['cert_list_type'] == 2:
                    pair = self.field(loc, lambda: sequence(entry, 2, 2))
                    if pair is not None:
                        output['certificate_digests'].append({
                            'type': self.field(loc + '/type', lambda: scalar(pair[0], core.PrintableString)),
                            'value': self.field(loc + '/value', lambda: binary(octets(pair[1])))})
                else:
                    self.issue('unknown_cert_list', loc, '未知授权证书列表类型，未推断授权关系。')
                    break
        return output

    def seal(self, node, location):
        fields = sequence(node, 4, 4)
        output = {"data": binary(node.raw), "verification": "not_performed"}
        info = self.field(location + '/eSealInfo', lambda: sequence(fields[0], 4, 5))
        if info is not None:
            header = self.field(location + '/header', lambda: sequence(info[0], 3, 3))
            if header is not None:
                for index, key, cls in [(0, 'id', core.IA5String), (1, 'version', core.Integer), (2, 'vendor', core.IA5String)]:
                    output[key] = self.field(location + '/' + key, lambda i=index, c=cls: scalar(header[i], c))
                if output.get('id') != 'ES' or output.get('version') != 4:
                    self.issue('unsupported_seal', location, '仅支持 ES / 版本 4 的电子印章属性结构。')
                else:
                    output['seal_id'] = self.field(location + '/esID', lambda: scalar(info[1], core.IA5String))
                    output['property'] = self.field(location + '/property', lambda: self.property(info[2], location + '/property'))
                    output['picture'] = self.field(location + '/picture', lambda: self.picture(info[3], location + '/picture'))
                    if len(info) == 5:
                        output['extensions'] = self.field(location + '/extensions', lambda: self.extensions(info[4], location + '/extensions'))
        output['maker_certificate'] = self.field(location + '/cert', lambda: self.certificate(octets(fields[1]), location + '/cert'))
        output['algorithm'] = self.field(location + '/signAlgID', lambda: scalar(fields[2], core.ObjectIdentifier))
        output['signature'] = self.field(location + '/signedValue', lambda:
            self.signature_value(bits(fields[3]), output['algorithm'], location + '/signedValue'))
        return output

    def timestamp(self, data, location):
        output = {'data': binary(data), 'verification': 'not_performed'}
        root(data)
        content = cms.ContentInfo.load(data, strict=True)
        output['content_type'] = content['content_type'].dotted
        if content['content_type'].native != 'signed_data':
            raise ValueError('时间戳不是 CMS SignedData')
        signed = content['content']
        encapsulated = signed['encap_content_info']
        if encapsulated['content_type'].native != 'tst_info':
            raise ValueError('时间戳封装内容不是 TSTInfo')
        encoded = encapsulated['content']
        if isinstance(encoded, core.Void):
            raise ValueError('时间戳缺少封装的 TSTInfo 内容')
        payload = encoded.parsed
        if not isinstance(payload, tsp.TSTInfo):
            raise ValueError('无法读取 TSTInfo')
        output.update({'policy': payload['policy'].dotted, 'serial': str(payload['serial_number'].native),
                       'declared_time': payload['gen_time'].native.isoformat(),
                       'imprint_algorithm': payload['message_imprint']['hash_algorithm']['algorithm'].dotted,
                       'imprint': binary(payload['message_imprint']['hashed_message'].native),
                       'signer_count': len(signed['signer_infos'])})
        return output

    def signature(self, data, location):
        output = {'data': binary(data), 'verification': 'not_performed'}
        fields = self.field(location, lambda: sequence(root(data), 4, 5))
        if fields is None:
            return output
        tbs = self.field(location + '/toSign', lambda: sequence(fields[0], 5, 6))
        if tbs is not None:
            output['version'] = self.field(location + '/version', lambda: scalar(tbs[0], core.Integer))
            if output['version'] != 4:
                self.issue('unsupported_signature', location, '仅解析 GB/T 38540—2020 的版本 4；旧版或其他格式保留数据摘要。')
                return output
            output['seal'] = self.field(location + '/eseal', lambda: self.seal(tbs[1], location + '/eseal'))
            output['declared_time'] = self.field(location + '/timeInfo', lambda: scalar(tbs[2], core.GeneralizedTime).isoformat())
            output['data_hash'] = self.field(location + '/dataHash', lambda: binary(bits(tbs[3])))
            output['property_info'] = self.field(location + '/propertyInfo', lambda: scalar(tbs[4], core.IA5String))
            if len(tbs) == 6:
                output['extensions'] = self.field(location + '/extDatas', lambda: self.extensions(tbs[5], location + '/extDatas', True))
        output['signer_certificate'] = self.field(location + '/cert', lambda: self.certificate(octets(fields[1]), location + '/cert'))
        output['algorithm'] = self.field(location + '/signatureAlgID', lambda: scalar(fields[2], core.ObjectIdentifier))
        output['signature'] = self.field(location + '/signature', lambda:
            self.signature_value(bits(fields[3]), output['algorithm'], location + '/signature'))
        output['timestamp'] = None
        if len(fields) == 5:
            def stamp():
                if fields[4].tag != 160 or len(fields[4].children()) != 1:
                    raise ValueError('timeStamp 应为 [0] EXPLICIT BIT STRING')
                raw = bits(fields[4].children()[0])
                # 即使 CMS 解码失败，也保留时间戳存在及摘要这一事实。
                return {'data': binary(raw), 'details': self.field(location + '/timeStamp/CMS', lambda: self.timestamp(raw, location + '/timeStamp'))}
            output['timestamp'] = self.field(location + '/timeStamp', stamp)
        return output
