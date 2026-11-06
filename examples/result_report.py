"""只演示结果模型；以下结果为人工构造，未读取文件或执行密码验证。"""

from sealverify import CheckResult, CheckSpec, CheckStatus, VerificationReport


def build_example() -> VerificationReport:
    return VerificationReport(
        source_name="合成示例（非真实验签结果）",
        planned_checks=(
            CheckSpec("signature-1", "signature", "签名值"),
            CheckSpec("signature-1", "certificate_chain", "证书链"),
            CheckSpec("signature-1", "timestamp", "时间戳", required=False),
        ),
        results=(
            CheckResult("signature-1", "signature", CheckStatus.PASSED, "人工构造的通过结果"),
            CheckResult(
                "signature-1", "certificate_chain", CheckStatus.INDETERMINATE,
                "示例缺少信任锚，无法形成可信链结论",
                remediation="补充可信材料后重新验证",
                context={"数据来源": "人工构造，仅用于演示模型"},
            ),
            CheckResult(
                "signature-1", "timestamp", CheckStatus.NOT_APPLICABLE,
                "本合成示例的演示策略未要求时间戳，不代表真实标准的适用性判定",
            ),
        ),
    )


if __name__ == "__main__":
    print(build_example().to_json())
