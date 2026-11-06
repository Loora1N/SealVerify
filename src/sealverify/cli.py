"""命令行入口与本地 OFD 阅读器。"""

import argparse
from importlib.metadata import version
from pathlib import Path
import sys
from typing import Optional, Sequence


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sealverify",
        description="SealVerify：本地 OFD 阅读器与电子签章验证基础模型。",
        epilog="密码验签和证书校验尚未实现；打开阅读不代表验证通过。",
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
    args = parser.parse_args(argv)
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
