"""
SmartLint Analyzer — main analysis engine.

Orchestrates AST parsing and runs all checkers on Solidity files.
"""

import os
from .ast_parser import parse_ast, ASTNode
from .models import AnalysisResult, Finding
from .checkers import CEIChecker, AccessControlChecker, UncheckedCallChecker


class Analyzer:
    """Main SmartLint analysis engine."""

    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a single Solidity file."""
        result = AnalysisResult(file_path=file_path)

        # Parse AST
        root, error, source_code = parse_ast(file_path)
        if root is None:
            result.parse_error = error
            return result

        # Count contracts and functions
        contracts = root.find_all("ContractDefinition")
        result.contracts_analyzed = len(contracts)
        result.functions_analyzed = sum(
            len(c.find_all("FunctionDefinition")) for c in contracts
        )

        # Run all checkers
        checkers = [
            CEIChecker(file_path, source_code),
            AccessControlChecker(file_path, source_code),
            UncheckedCallChecker(file_path, source_code),
        ]

        for checker in checkers:
            try:
                findings = checker.check(root)
                result.findings.extend(findings)
            except Exception as e:
                result.findings.append(Finding(
                    severity=__import__("smartlint.models", fromlist=["Severity"]).Severity.INFO,
                    checker=__import__("smartlint.models", fromlist=["CheckerType"]).CheckerType.CEI,
                    title="Checker Error",
                    message=f"Error in {checker.__class__.__name__}: {e}",
                    location=__import__("smartlint.models", fromlist=["SourceLocation"]).SourceLocation(file_path),
                ))

        return result

    def analyze_directory(self, dir_path: str) -> list[AnalysisResult]:
        """Analyze all .sol files in a directory (recursively)."""
        results = []

        for root_dir, _dirs, files in os.walk(dir_path):
            for filename in sorted(files):
                if filename.endswith(".sol"):
                    file_path = os.path.join(root_dir, filename)
                    result = self.analyze_file(file_path)
                    results.append(result)

        return results

    def analyze(self, path: str) -> list[AnalysisResult]:
        """Analyze a file or directory."""
        if os.path.isfile(path):
            return [self.analyze_file(path)]
        elif os.path.isdir(path):
            return self.analyze_directory(path)
        else:
            return [AnalysisResult(
                file_path=path,
                parse_error=f"Path not found: {path}",
            )]
