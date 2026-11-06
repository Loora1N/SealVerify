"""SealVerify 的验证计划和结果模型。业务验证器尚未实现。"""

from .results import CheckResult, CheckSpec, CheckStatus, OverallStatus, VerificationReport

__all__ = [
    "CheckResult",
    "CheckSpec",
    "CheckStatus",
    "OverallStatus",
    "VerificationReport",
]
