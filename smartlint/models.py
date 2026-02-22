"""
Data models for SmartLint findings and analysis results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckerType(Enum):
    CEI = "CEI"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    UNCHECKED_CALL = "UNCHECKED_CALL"


# Move guarantee descriptions for each checker
MOVE_GUARANTEES = {
    CheckerType.CEI: (
        "In Move, this vulnerability class is structurally eliminated: "
        "the resource model ensures that state changes are completed before "
        "any cross-module interactions occur, and the absence of arbitrary "
        "external calls prevents reentrancy by design."
    ),
    CheckerType.ACCESS_CONTROL: (
        "In Move, access control is enforced through capability resources. "
        "A function requiring admin privileges would demand the caller possess "
        "an AdminCap resource, making unauthorized access a type error caught "
        "at compilation time, not a runtime check that can be forgotten."
    ),
    CheckerType.UNCHECKED_CALL: (
        "In Move, all operations that may fail must have their results "
        "explicitly handled. The type system prevents ignoring error "
        "conditions, eliminating the class of bugs caused by unchecked "
        "call results."
    ),
}


@dataclass
class SourceLocation:
    """Location in the Solidity source file."""
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    src: str = ""  # raw "offset:length:fileIndex" from AST

    def __str__(self):
        if self.line_start:
            return f"{self.file_path}:{self.line_start}"
        return self.file_path


@dataclass
class Finding:
    """A single finding reported by a checker."""
    severity: Severity
    checker: CheckerType
    title: str
    message: str
    location: SourceLocation
    move_guarantee: str = ""
    function_name: str = ""
    contract_name: str = ""

    def __post_init__(self):
        if not self.move_guarantee:
            self.move_guarantee = MOVE_GUARANTEES.get(self.checker, "")

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "checker": self.checker.value,
            "title": self.title,
            "message": self.message,
            "location": str(self.location),
            "function": self.function_name,
            "contract": self.contract_name,
            "move_guarantee": self.move_guarantee,
        }


@dataclass
class AnalysisResult:
    """Result of analyzing a single Solidity file."""
    file_path: str
    findings: list[Finding] = field(default_factory=list)
    contracts_analyzed: int = 0
    functions_analyzed: int = 0
    parse_error: Optional[str] = None

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def findings_by_checker(self, checker: CheckerType) -> list[Finding]:
        return [f for f in self.findings if f.checker == checker]

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "contracts_analyzed": self.contracts_analyzed,
            "functions_analyzed": self.functions_analyzed,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "parse_error": self.parse_error,
        }
