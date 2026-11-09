"""生成结构测试用签章；证书和签名值均为人工构造，绝不能用于验签通过样例。"""

import argparse
from datetime import datetime, timezone
import hashlib
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from asn1crypto import core, x509, keys, cms, tsp

try:
    from .create_reading_demo import build_demo, png, NS
except ImportError:
    from create_reading_demo import build_demo, png, NS


class Header(core.Sequence):
    _fields = [('id', core.IA5String), ('version', core.Integer), ('vendor', core.IA5String)]


class CertList(core.SequenceOf):
    _child_spec = core.OctetString


class Digest(core.Sequence):
    _fields = [('type', core.PrintableString), ('value', core.OctetString)]


class DigestList(core.SequenceOf):
    _child_spec = Digest


class Property(core.Sequence):
    _fields = [('type', core.Integer), ('name', core.UTF8String), ('cert_type', core.Integer),
               ('certs', core.Any), ('created', core.GeneralizedTime),
               ('start', core.GeneralizedTime), ('end', core.GeneralizedTime)]


class Picture(core.Sequence):
    _fields = [('type', core.IA5String), ('data', core.OctetString), ('width', core.Integer), ('height', core.Integer)]


class Extension(core.Sequence):
    _fields = [('oid', core.ObjectIdentifier), ('critical', core.Boolean, {'default': False}), ('value', core.OctetString)]


class Extensions(core.SequenceOf):
    _child_spec = Extension


class SealInfo(core.Sequence):
    _fields = [('header', Header), ('id', core.IA5String), ('property', Property), ('picture', Picture),
               ('extensions', Extensions, {'optional': True})]


class Seal(core.Sequence):
    _fields = [('info', SealInfo), ('cert', core.OctetString), ('algorithm', core.ObjectIdentifier), ('signature', core.OctetBitString)]


class TBS(core.Sequence):
    _fields = [('version', core.Integer), ('seal', Seal), ('time', core.GeneralizedTime),
               ('hash', core.OctetBitString), ('property', core.IA5String),
               ('extensions', Extensions, {'explicit': 0, 'optional': True})]


class Signature(core.Sequence):
    _fields = [('tbs', TBS), ('cert', core.OctetString), ('algorithm', core.ObjectIdentifier),
               ('signature', core.OctetBitString), ('timestamp', core.OctetBitString, {'explicit': 0, 'optional': True})]


TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
ALG = '1.2.156.10197.1.501'


class IntegerPair(core.Sequence):
    _fields = [('r', core.Integer), ('s', core.Integer)]


def sm2_value(number=1):
    # 仅结构样例：r 需要 DER 正号补零，s 是短整数；未计算真实签名。
    return IntegerPair({'r': (1 << 255) + number, 's': number + 1}).dump()


def certificate(name, *, sm2=False):
    public_key = keys.PublicKeyInfo({'algorithm': {'algorithm': 'rsa'},
        'public_key': keys.RSAPublicKey({'modulus': 3233, 'public_exponent': 17})})
    if sm2:
        # 仅算法声明与编码样例，点字节是合成数据，未声称曲线点或证书有效。
        public_key = keys.PublicKeyInfo({'algorithm': {'algorithm': 'ec',
            'parameters': keys.ECDomainParameters(name='named', value='1.2.156.10197.1.301')},
            'public_key': b'\x04' + bytes(range(64))})
    return x509.Certificate({
        'tbs_certificate': {'version': 'v3', 'serial_number': 1001,
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': x509.Name.build({'common_name': 'Synthetic issuer - NOT TRUSTED'}),
            'subject': x509.Name.build({'common_name': name}),
            'validity': {'not_before': x509.Time({'utc_time': TIME}),
                         'not_after': x509.Time({'utc_time': datetime(2030, 1, 1, tzinfo=timezone.utc)})},
            'subject_public_key_info': public_key,
            'extensions': [x509.Extension({'extn_id': 'basic_constraints', 'critical': True,
                                          'extn_value': x509.BasicConstraints({'ca': False})})]},
        'signature_algorithm': {'algorithm': 'sha256_rsa'}, 'signature_value': b'FAKE certificate signature',
    }).dump()


def timestamp():
    info = tsp.TSTInfo({'version': 'v1', 'policy': '1.2.3.4', 'message_imprint': {
        'hash_algorithm': {'algorithm': 'sha256'}, 'hashed_message': bytes(32)},
        'serial_number': 1, 'gen_time': TIME})
    return cms.ContentInfo({'content_type': 'signed_data', 'content': cms.SignedData({
        'version': 'v3', 'digest_algorithms': [{'algorithm': 'sha256'}],
        'encap_content_info': {'content_type': 'tst_info', 'content': info},
        'signer_infos': [],
    })}).dump()


def signature(number=1, *, digest_list=False, with_timestamp=False, bad_certificate=False, rsa=False):
    signer = certificate('Synthetic signer %s' % number, sm2=not rsa)
    certs = DigestList([{'type': 'SHA256', 'value': hashlib.sha256(signer).digest()}]) if digest_list else CertList([signer])
    extension = [{'oid': '1.2.3.4.5', 'critical': False, 'value': b'synthetic extension'}]
    seal = Seal({'info': {'header': {'id': 'ES', 'version': 4, 'vendor': 'SealVerify demo'},
        'id': 'synthetic-seal-%s' % number,
        'property': {'type': 1, 'name': '合成测试印章 %s（未验证）' % number,
                     'cert_type': 2 if digest_list else 1, 'certs': certs,
                     'created': TIME, 'start': TIME, 'end': datetime(2030, 1, 1, tzinfo=timezone.utc)},
        'picture': {'type': 'PNG', 'data': png(), 'width': 40, 'height': 25}, 'extensions': extension},
        'cert': certificate('Synthetic maker', sm2=True), 'algorithm': ALG, 'signature': sm2_value(number + 10)})
    value = Signature({'tbs': {'version': 4, 'seal': seal, 'time': TIME,
        'hash': bytes(32), 'property': 'synthetic coverage declaration', 'extensions': extension},
        'cert': b'broken certificate' if bad_certificate else signer, 'algorithm': ALG,
        'signature': sm2_value(number)})
    if rsa:
        # 特意保留前导 00 和末尾 ff，便于验收完整字节展示。
        value['algorithm'] = '1.2.840.113549.1.1.11'
        value['signature'] = bytes(range(256))
    if with_timestamp:
        value['timestamp'] = timestamp()
    return value


def build_signed_demo(*, broken=False, multiple_documents=False, rsa=False, format_errors=False, seal_errors=False):
    with ZipFile(BytesIO(build_demo(multiple_documents=multiple_documents))) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    ofd = entries['OFD.xml'].decode('utf-8')
    ofd = ofd.replace('</ofd:DocBody>', '<ofd:Signatures>Doc_0/Signs/Signatures.xml</ofd:Signatures></ofd:DocBody>', 1)
    if multiple_documents:
        at = ofd.rfind('</ofd:DocBody>')
        ofd = ofd[:at] + '<ofd:Signatures>Doc_1/Signs/Signatures.xml</ofd:Signatures>' + ofd[at:]
    entries['OFD.xml'] = ofd.encode('utf-8')
    for doc in range(2 if multiple_documents else 1):
        base = 'Doc_%s/Signs/' % doc
        sigs = ''
        for index in range(2 if doc == 0 else 1):
            folder = base + 'Sign_%s/' % index
            sigs += '<ofd:Signature ID="%s" Type="Seal" BaseLoc="Sign_%s/Signature.xml"/>' % (index + 1, index)
            value = signature(index + 1, with_timestamp=index == 1 and not (format_errors or seal_errors), rsa=rsa)
            if format_errors and index == 0:
                value['tbs']['version'] = 3
                value['tbs']['seal']['info']['header']['id'] = 'BAD'
                value['tbs']['hash'] = bytes(31)
                value['tbs']['property'] = ''
                value['cert'] = b'broken certificate'
                value['signature'] = b'broken SM2 encoding'
            # 外置资源先保留正常格式，用于证明坏内嵌印章不阻断独立外置检查。
            entries[folder + 'Seal.esl'] = value['tbs']['seal'].dump()
            if seal_errors and index == 0:
                seal = value['tbs']['seal']
                seal['info']['header']['id'] = 'BAD'
                seal['info']['property']['cert_type'] = 9
                seal['info']['picture']['data'] = b'broken PNG'
                seal['cert'] = b'broken maker certificate'
                seal['signature'] = b'broken SM2 encoding'
            entries[folder + 'SignedValue.dat'] = b'bad ASN.1' if broken and index == 0 else value.dump()
            page = '900' if doc else ('10' if index == 0 else '13')
            entries[folder + 'Signature.xml'] = (f'<ofd:Signature {NS}><ofd:SignedInfo>'
                f'<ofd:Provider ProviderName="Synthetic" Version="1"/><ofd:SignatureMethod>{value["algorithm"].native}</ofd:SignatureMethod>'
                '<ofd:SignatureDateTime>2026-01-01T00:00:00Z</ofd:SignatureDateTime>'
                '<ofd:References CheckMethod="1.2.156.10197.1.401"><ofd:Reference FileRef="/OFD.xml">'
                '<ofd:CheckValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ofd:CheckValue></ofd:Reference></ofd:References>'
                f'<ofd:StampAnnot ID="{700 + index}" PageRef="{page}" Boundary="120 160 40 25"/>'
                '<ofd:Seal><ofd:BaseLoc>Seal.esl</ofd:BaseLoc></ofd:Seal></ofd:SignedInfo>'
                '<ofd:SignedValue>SignedValue.dat</ofd:SignedValue></ofd:Signature>').encode('utf-8')
        entries[base + 'Signatures.xml'] = (f'<ofd:Signatures {NS}>{sigs}</ofd:Signatures>').encode('utf-8')
    output = BytesIO()
    with ZipFile(output, 'w') as archive:
        for name, data in entries.items():
            info = ZipInfo(name, (2026, 1, 1, 0, 0, 0)); info.compress_type = ZIP_DEFLATED
            archive.writestr(info, data)
    return output.getvalue()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--broken', action='store_true')
    parser.add_argument('--multiple-documents', action='store_true')
    parser.add_argument('--rsa', action='store_true', help='电子签章使用 RSA 算法标识和合成字节串')
    parser.add_argument('--format-errors', action='store_true', help='首个签章含多处格式错误，后续签章仍可检查')
    parser.add_argument('--seal-errors', action='store_true', help='首个内嵌印章含多处格式错误；外置资源与后续印章保持可检查')
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(build_signed_demo(broken=args.broken, multiple_documents=args.multiple_documents,
                                            rsa=args.rsa, format_errors=args.format_errors, seal_errors=args.seal_errors))
    print('已生成结构测试样例（签名和证书不可用于验签）。')
