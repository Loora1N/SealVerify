"""与具体解析器、密码库和用户界面无关的结果契约。"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"
    SKIPPED = "skipped"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class OverallStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(name + " must be a non-empty string")


@dataclass(frozen=True)
class CheckSpec:
    """计划中的一项检查；对象 ID 区分同一文件中的多个签章。"""

    object_id: str
    check_id: str
    label: str
    required: bool = True

    def __post_init__(self) -> None:
        for name in ("object_id", "check_id", "label"):
            _require_text(name, getattr(self, name))
        if not isinstance(self.required, bool):
            raise TypeError("required must be bool")

    @property
    def key(self) -> Tuple[str, str]:
        return self.object_id, self.check_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_id": self.object_id,
            "check_id": self.check_id,
            "label": self.label,
            "required": self.required,
        }


@dataclass(frozen=True)
class CheckResult:
    """单项实际结果。所有状态都必须有说明，包括跳过和不适用。"""

    object_id: str
    check_id: str
    status: CheckStatus
    message: str
    location: Optional[str] = None
    expected: Optional[str] = None
    actual: Optional[str] = None
    standard_reference: Optional[str] = None
    remediation: Optional[str] = None
    context: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("object_id", "check_id", "message"):
            _require_text(name, getattr(self, name))
        if not isinstance(self.status, CheckStatus):
            raise TypeError("status must be CheckStatus")
        for name in ("location", "expected", "actual", "standard_reference", "remediation"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise TypeError(name + " must be a string or None")
        if not isinstance(self.context, Mapping):
            raise TypeError("context must be a mapping of strings")
        context = dict(self.context)
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in context.items()):
            raise TypeError("context keys and values must be strings")
        object.__setattr__(self, "context", MappingProxyType(context))

    @property
    def key(self) -> Tuple[str, str]:
        return self.object_id, self.check_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_id": self.object_id,
            "check_id": self.check_id,
            "status": self.status.value,
            "message": self.message,
            "location": self.location,
            "expected": self.expected,
            "actual": self.actual,
            "standard_reference": self.standard_reference,
            "remediation": self.remediation,
            "context": dict(self.context),
        }


@dataclass(frozen=True)
class VerificationReport:
    """汇总已声明的计划；不会把漏报或零检查视为验证通过。"""

    source_name: str
    planned_checks: Tuple[CheckSpec, ...]
    results: Tuple[CheckResult, ...] = ()
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        _require_text("source_name", self.source_name)
        if not isinstance(self.generated_at, datetime) or self.generated_at.utcoffset() is None:
            raise ValueError("generated_at must be a timezone-aware datetime")
        planned_checks, results = tuple(self.planned_checks), tuple(self.results)
        if any(not isinstance(item, CheckSpec) for item in planned_checks):
            raise TypeError("planned_checks must contain CheckSpec instances")
        if any(not isinstance(item, CheckResult) for item in results):
            raise TypeError("results must contain CheckResult instances")
        plan_keys = {item.key for item in planned_checks}
        result_keys = {item.key for item in results}
        if len(plan_keys) != len(planned_checks):
            raise ValueError("duplicate planned check for the same object")
        if len(result_keys) != len(results):
            raise ValueError("duplicate result for the same object and check")
        if not result_keys <= plan_keys:
            raise ValueError("result does not belong to the declared plan")
        object.__setattr__(self, "planned_checks", planned_checks)
        object.__setattr__(self, "results", results)

    @property
    def missing_checks(self) -> Tuple[CheckSpec, ...]:
        reported = {item.key for item in self.results}
        return tuple(item for item in self.planned_checks if item.key not in reported)

    @property
    def overall_status(self) -> OverallStatus:
        if any(item.status == CheckStatus.FAILED for item in self.results):
            return OverallStatus.FAILED
        if not self.planned_checks or self.missing_checks:
            return OverallStatus.INCOMPLETE
        by_key = {item.key: item for item in self.results}
        applicable = [
            by_key[spec.key]
            for spec in self.planned_checks
            if spec.required and by_key[spec.key].status != CheckStatus.NOT_APPLICABLE
        ]
        if not applicable or any(item.status != CheckStatus.PASSED for item in applicable):
            return OverallStatus.INCOMPLETE
        return OverallStatus.PASSED

    def to_dict(self) -> Dict[str, Any]:
        """导出完整计划、结果和缺项；generated_at 不是可信签章时间。"""
        counts = {status.value: 0 for status in CheckStatus}
        for result in self.results:
            counts[result.status.value] += 1
        return {
            "schema_version": "1.0",
            "source_name": self.source_name,
            "generated_at": self.generated_at.isoformat(),
            "overall_status": self.overall_status.value,
            "summary": {
                "planned": len(self.planned_checks),
                "reported": len(self.results),
                "missing": len(self.missing_checks),
                "by_status": counts,
            },
            "planned_checks": [item.to_dict() for item in self.planned_checks],
            "checks": [item.to_dict() for item in self.results],
            "missing_checks": [item.to_dict() for item in self.missing_checks],
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
