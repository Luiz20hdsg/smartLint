"""
Base class for all SmartLint checkers.
"""

from abc import ABC, abstractmethod
from ..ast_parser import ASTNode
from ..models import Finding, SourceLocation


class BaseChecker(ABC):
    """Abstract base class for security checkers."""

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code

    @abstractmethod
    def check(self, root: ASTNode) -> list[Finding]:
        """Run the checker on the AST and return findings."""
        ...

    def _make_location(self, node: ASTNode) -> SourceLocation:
        """Create a SourceLocation from an AST node."""
        return SourceLocation(
            file_path=self.file_path,
            line_start=node.get_line_number(),
            src=node.src,
        )

    def _get_contract_name(self, node: ASTNode, root: ASTNode) -> str:
        """Try to find the contract name that contains a given node."""
        node_offset = node.get_source_offset()
        for contract in root.find_all("ContractDefinition"):
            c_start = contract.get_source_offset()
            c_end = c_start + contract.get_source_length()
            if c_start <= node_offset <= c_end:
                return contract.name
        return "<unknown>"
