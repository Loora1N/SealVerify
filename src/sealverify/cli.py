"""M1 基础命令行入口，不接受文件并伪造验签结果。"""

import argparse
from importlib.metadata import version
from typing import Optional, Sequence


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sealverify",
        description="SealVerify 电子签章验证工具：当前提供基础入口与结果模型。",
        epilog="OFD 解析、密码验签和证书校验尚未实现。",
    )
    parser.add_argument(
        "--version", action="version", version="SealVerify " + version("sealverify")
    )
    parser.parse_args(argv)
    parser.print_help()
    return 0
