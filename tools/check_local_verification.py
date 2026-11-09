"""检查私有 M3 基准；需要单独核验后登记的清单，不自动重建预期。"""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

from sealverify.verification import verify_ofd


def snapshot(report):
    return [{'checked_status': s['m3_validation']['checked_status'],
             'overall_status': s['m3_validation']['overall_status'],
             'checks': {c['check_id']: c['status'] for c in s['m3_validation']['checks']}}
            for d in report['documents'] for s in d['signatures']]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=Path('local-data/m3-samples.json'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        original = json.loads((root / 'local-data/local-samples.json').read_text(encoding='utf-8'))
        registered = {item['path']: item['sha256'] for item in original['samples']}
        if not manifest['samples'] or {s['path'] for s in manifest['samples']} != registered.keys():
            raise ValueError('M3 清单未完整覆盖原基准')
        for number, item in enumerate(manifest['samples'], 1):
            path = (root / item['path']).resolve()
            path.relative_to(root)
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != item['sha256'] or item['sha256'] != registered[item['path']]:
                raise ValueError('基准 %s 原件改变或与原清单不一致；未自动重建预期' % number)
            report = verify_ofd(data, at=datetime.fromisoformat(manifest['verification_time']))
            if snapshot(report) != item['expected']:
                raise ValueError('基准 %s 的 M3 结果与独立核验后的预期不一致' % number)
            if path.read_bytes() != data:
                raise ValueError('原件被修改')
        print('本地 %s 个 OFD 基准的 M3 逐项结果与固定预期一致；不表示整体签章有效。' % len(manifest['samples']))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print('M3 本地基准回归失败：' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
