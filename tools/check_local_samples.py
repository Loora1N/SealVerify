"""按本地清单检查 OFD 基准；清单和原件不随仓库分发，缺失或变更直接失败。"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from sealverify.inspection import inspect_ofd


def snapshot(report):
    return {'parse_status': report['parse_status'], 'verification': report['verification'],
        'documents': [{'pages': d['pages'], 'signatures': [{
            'id': s['id'], 'parse_status': s['parse_status'], 'placements': s['placements'],
            'algorithm': s.get('algorithm'), 'declared_time': s.get('declared_time'),
            'references': s['references'], 'signed_value': s.get('signed_value'),
            'external_seal': s.get('external_seal'),
        } for s in d['signatures']]} for d in report['documents']]}


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
            if path.read_bytes() != data:
                raise ValueError('原件被修改')
        print('本地 %s 个 OFD 基准的原件哈希、属性及页面关联回归通过。' % len(manifest['samples']))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        # 不输出证书、正文或完整报告；缺失不能当成跳过后的通过。
        print('本地基准回归失败：' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
