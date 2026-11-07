"""按本地清单检查 OFD 基准；清单和原件不随仓库分发，缺失或变更直接失败。"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
from io import BytesIO
from zipfile import ZipFile

from asn1crypto import algos, core, x509

from sealverify.inspection import inspect_ofd


def snapshot(report):
    return legacy_fields({'parse_status': report['parse_status'], 'verification': report['verification'],
        'documents': [{'pages': d['pages'], 'signatures': [{
            'id': s['id'], 'parse_status': s['parse_status'], 'placements': s['placements'],
            'algorithm': s.get('algorithm'), 'declared_time': s.get('declared_time'),
            'references': s['references'], 'signed_value': s.get('signed_value'),
            'external_seal': s.get('external_seal'),
        } for s in d['signatures']]} for d in report['documents']]})


def legacy_fields(value):
    """仅投影本次新增的两个字段；原有预期清单逐字节保留，不重新登记。"""
    if isinstance(value, list):
        return [legacy_fields(item) for item in value]
    if isinstance(value, dict):
        return {key: legacy_fields(item) for key, item in value.items()
                if key != 'certificate_signature' and not (key == 'decoded' and 'hex_preview' in value)}
    return value


def verify_signature_values(data, report):
    """用独立 ASN.1 类型重新编码 r/s，并对照原件内证书的签名值。"""
    certificates = {}
    def add_certificate(raw):
        certificates[hashlib.sha256(raw).hexdigest()] = x509.Certificate.load(raw, strict=True)['signature_value'].native
    def collect_seal(seal):
        add_certificate(seal[1].native)
        prop = seal[0][2]
        if prop[2].native == 1:
            for index in range(len(prop[3])):
                add_certificate(prop[3][index].native)
    with ZipFile(BytesIO(data)) as archive:
        for doc in report['documents']:
            for sig in doc['signatures']:
                value = core.Sequence.load(archive.read(sig['signed_value_path']), strict=True)
                add_certificate(value[1].native)
                collect_seal(value[0][1])
                if sig.get('external_seal_path'):
                    collect_seal(core.Sequence.load(archive.read(sig['external_seal_path']), strict=True))
    count = 0
    def visit(value):
        nonlocal count
        if isinstance(value, list):
            for item in value:
                visit(item)
        if not isinstance(value, dict):
            return
        if 'certificate_signature' in value:
            raw = certificates[value['data']['sha256']]
            if hashlib.sha256(raw).hexdigest() != value['certificate_signature']['sha256']:
                raise ValueError('证书签名内容与原始证书不一致')
        if 'decoded' in value and 'hex_preview' in value:
            decoded = value['decoded']
            if decoded['status'] != 'decoded':
                raise ValueError('基准内签名值未能按算法解析')
            if decoded['algorithm'] == 'SM2':
                if len(decoded['r_hex']) != 64 or len(decoded['s_hex']) != 64:
                    raise ValueError('SM2 分量长度不符合 32 字节展示约定')
                raw = algos.DSASignature({'r': int(decoded['r_hex'], 16), 's': int(decoded['s_hex'], 16)}).dump()
            else:
                raw = bytes.fromhex(decoded['signature_hex'])
            if len(raw) != value['bytes'] or hashlib.sha256(raw).hexdigest() != value['sha256']:
                raise ValueError('完整签名展示与原始签名数据摘要不一致')
            count += 1
        for item in value.values():
            visit(item)
    visit(report)
    if not count:
        raise ValueError('本地基准未覆盖签名值展示')
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=Path('local-data/local-samples.json'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        if not manifest['samples']:
            raise ValueError('基准清单为空')
        for number, item in enumerate(manifest['samples'], 1):
            path = (root / item['path']).resolve()
            path.relative_to(root)
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('基准 %s 的原件发生变化；需人工核对，未自动重建基准' % number)
            report = inspect_ofd(data)
            if snapshot(report) != item['expected']:
                raise ValueError('基准 %s 的结构结果与已登记预期不符' % number)
            verify_signature_values(data, report)
            if path.read_bytes() != data:
                raise ValueError('原件被修改')
        print('本地 %s 个 OFD 基准的原件、既有属性、页面关联及完整签名内容回归通过。' % len(manifest['samples']))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        # 不输出证书、正文或完整报告；缺失不能当成跳过后的通过。
        print('本地基准回归失败：' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
