"""命令行入口与本地 OFD 阅读器。"""

import argparse
import json
from importlib.metadata import version
from pathlib import Path
import sys
from typing import Optional, Sequence


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sealverify",
        description="SealVerify：本地 OFD 阅读器与电子签章验证基础模型。",
        epilog="verify 执行 M3 验签与杂凑检查；证书信任、吊销及可信时间尚未完成。",
    )
    parser.add_argument(
        "--version", action="version", version="SealVerify " + version("sealverify")
    )
    commands = parser.add_subparsers(dest="command")
    view = commands.add_parser("view", help="打开本地 OFD 阅读器")
    view.add_argument("file", nargs="?", type=Path, help="可选的 OFD 文件路径")
    view.add_argument("--demo", action="store_true", help="打开内置合成阅读示例")
    view.add_argument("--no-browser", action="store_true", help="只打印地址，不自动打开浏览器")
    view.add_argument("--port", type=int, default=0, help="本机端口，默认随机选择空闲端口")
    inspect = commands.add_parser('inspect', help='输出 OFD 签章属性 JSON（不执行验签）')
    inspect.add_argument('file', type=Path, help='本地 OFD 文件')
    check_format = commands.add_parser('check-format', help='逐项诊断电子签章数据格式，错误记录后继续检查')
    check_format.add_argument('file', type=Path, help='本地 OFD 文件')
    check_seal = commands.add_parser('check-seal-format', help='检查 OFD 内嵌/外置印章格式，或独立印章 DER')
    check_seal.add_argument('file', type=Path, help='本地 OFD 或印章 DER 文件')
    check_seal.add_argument('--seal', action='store_true', help='将输入作为独立 SESeal DER（如 .esl）检查')
    verify = commands.add_parser('verify', help='执行 M3 密码验签、授权匹配和原始字节杂凑验证')
    verify.add_argument('file', type=Path, help='本地 OFD 文件')
    verify.add_argument('--sm2-id', default='1234567812345678', help='SM2 用户标识，以 UTF-8 编码；默认 1234567812345678')
    args = parser.parse_args(argv)
    if args.command in ('inspect', 'check-format', 'check-seal-format', 'verify'):
        from .inspection import inspect_ofd, MAX_FILE_BYTES
        try:
            with args.file.open('rb') as stream:
                if args.command == 'verify':
                    from .verification import verify_ofd
                    uid = args.sm2_id.encode('utf-8')
                    if not 1 <= len(uid) <= 8191:
                        parser.error('SM2 用户标识需要 1–8191 字节')
                    report = verify_ofd(stream.read(MAX_FILE_BYTES + 1), sm2_id=uid)
                elif args.command == 'check-seal-format' and args.seal:
                    from .inspection.format import check_seal_format
                    report = check_seal_format(stream.read(16 * 1024 * 1024 + 1), args.file.name)
                else:
                    report = inspect_ofd(stream.read(MAX_FILE_BYTES + 1))
            print(json.dumps(report, ensure_ascii=False, indent=2))
            if args.command == 'verify':
                return 0 if report['m3_validation']['overall_status'] == 'passed' else 1
            if args.command == 'check-format':
                return 0 if all(report[k]['overall_status'] == 'passed' for k in ('format_validation', 'seal_format_validation')) else 1
            if args.command == 'check-seal-format':
                result = report if args.seal else report['seal_format_validation']
                return 0 if result['overall_status'] == 'passed' else 1
            return 0 if report['parse_status'] == 'parsed' else 1
        except OSError as exc:
            print('无法读取文件：' + str(exc), file=sys.stderr)
            return 1
    if args.command == "view":
        if not 0 <= args.port <= 65535:
            parser.error("端口必须在 0–65535 之间。")
        if args.file and args.demo:
            parser.error("文件路径和 --demo 不能同时使用。")
        from .reader import serve
        try:
            return serve(args.file, port=args.port, open_browser=not args.no_browser,
                         demo=args.demo)
        except (OSError, ValueError) as exc:
            print("无法打开阅读器：" + str(exc), file=sys.stderr)
            return 1
    parser.print_help()
    return 0
