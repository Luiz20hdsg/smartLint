"""
Unchecked External Call Checker — Detects low-level calls with unchecked returns.

Detects low-level calls (call, delegatecall, staticcall) whose boolean
return values are not checked, which can lead to silent failures.

In Move, all operations that may fail must have their results explicitly
handled by the type system.
"""

from ..ast_parser import ASTNode
from ..models import Finding, Severity, CheckerType
from .base import BaseChecker


class UncheckedCallChecker(BaseChecker):
    """Detects low-level calls whose return values are not checked."""

    LOW_LEVEL_CALLS = {"call", "delegatecall", "staticcall", "send"}

    def check(self, root: ASTNode) -> list[Finding]:
        findings = []

        for contract in root.find_all("ContractDefinition"):
            contract_kind = contract.raw.get("contractKind", "contract")
            if contract_kind in ("interface", "library"):
                continue

            for func in contract.find_all("FunctionDefinition"):
                if func.body is None:
                    continue

                func_findings = self._check_function(func, contract.name, root)
                findings.extend(func_findings)

        return findings

    def _check_function(
        self, func: ASTNode, contract_name: str, root: ASTNode
    ) -> list[Finding]:
        """Check a single function for unchecked low-level calls."""
        findings = []

        for node in func.body.walk():
            if not self._is_low_level_call(node):
                continue

            call_type = self._get_call_type(node)

            # Check if this call is part of a VariableDeclarationStatement
            # or an assignment that captures the return value
            if self._is_return_checked(node, func.body):
                continue

            findings.append(Finding(
                severity=Severity.MEDIUM,
                checker=CheckerType.UNCHECKED_CALL,
                title="Unchecked Low-Level Call",
                message=(
                    f"Low-level '{call_type}' at line {node.get_line_number()} "
                    f"has its return value unchecked. If the call fails, "
                    f"execution will continue silently with inconsistent state."
                ),
                location=self._make_location(node),
                function_name=func.name,
                contract_name=contract_name,
            ))

        return findings

    def _is_low_level_call(self, node: ASTNode) -> bool:
        """Check if a node is a low-level call."""
        if node.node_type != "FunctionCall":
            return False

        expr = node.expression
        if expr is None:
            return False

        # addr.call(...), addr.delegatecall(...), addr.staticcall(...)
        if expr.node_type == "MemberAccess":
            return expr.member_name in self.LOW_LEVEL_CALLS

        # addr.call{value: x}(...)
        if expr.node_type == "FunctionCallOptions":
            inner = expr.expression
            if inner and inner.node_type == "MemberAccess":
                return inner.member_name in self.LOW_LEVEL_CALLS

        return False

    def _get_call_type(self, node: ASTNode) -> str:
        """Get the type of low-level call (call, delegatecall, staticcall)."""
        expr = node.expression
        if expr.node_type == "MemberAccess":
            return expr.member_name
        if expr.node_type == "FunctionCallOptions":
            inner = expr.expression
            if inner and inner.node_type == "MemberAccess":
                return inner.member_name
        return "call"

    def _is_return_checked(self, call_node: ASTNode, func_body: ASTNode) -> bool:
        """
        Determine if a low-level call's return value is properly checked.

        A return is considered "checked" if:
        1. It's captured in a variable declaration: (bool success, ) = addr.call(...)
           AND the success variable is used in a require/assert/if
        2. It's directly inside a require: require(addr.call(...))
        """
        call_offset = call_node.get_source_offset()
        call_end = call_offset + call_node.get_source_length()

        # Walk the function body to find the statement containing this call
        for stmt in func_body.walk():
            stmt_offset = stmt.get_source_offset()
            stmt_end = stmt_offset + stmt.get_source_length()

            # The call must be within this statement
            if not (stmt_offset <= call_offset and call_end <= stmt_end):
                continue

            # Case 1: VariableDeclarationStatement that captures the return
            # e.g., (bool success, ) = addr.call{value: amount}("")
            if stmt.node_type == "VariableDeclarationStatement":
                # The call's return is captured; now check if the bool is used
                decls = stmt.declarations
                if decls:
                    first_decl = decls[0]
                    var_id = first_decl.id
                    var_name = first_decl.name
                    # Check if this variable is used in a require/assert/if later
                    if self._is_var_checked_after(var_id, var_name, stmt, func_body):
                        return True

            # Case 2: Expression wrapped in require()
            # require(addr.send(amount))
            if stmt.node_type == "ExpressionStatement":
                expr = stmt.expression
                if expr and expr.node_type == "FunctionCall":
                    fn_expr = expr.expression
                    if fn_expr and fn_expr.node_type == "Identifier":
                        if fn_expr.name in ("require", "assert"):
                            # Check if the call is an argument
                            for arg in expr.arguments:
                                if self._contains_node(arg, call_node):
                                    return True

            # Case 3: Assignment where result is checked
            # bool success = ...; require(success);
            if stmt.node_type == "ExpressionStatement":
                expr = stmt.expression
                if expr and expr.node_type == "Assignment":
                    lhs = expr.left_hand_side
                    if lhs and lhs.node_type == "TupleExpression":
                        # Tuple assignment: (success, ) = addr.call(...)
                        # Check components
                        components = lhs.raw.get("components", [])
                        if components and components[0]:
                            comp = ASTNode(components[0], self.source_code)
                            ref_id = comp.referenced_declaration
                            if ref_id and self._is_var_checked_after(
                                ref_id, comp.name, stmt, func_body
                            ):
                                return True

        return False

    def _is_var_checked_after(
        self, var_id: int, var_name: str, stmt: ASTNode, func_body: ASTNode
    ) -> bool:
        """Check if a variable is used in a require/assert/if after the given statement."""
        stmt_offset = stmt.get_source_offset()

        for node in func_body.walk():
            if node.get_source_offset() <= stmt_offset:
                continue

            # require(success) or assert(success)
            if node.node_type == "FunctionCall":
                fn_expr = node.expression
                if fn_expr and fn_expr.node_type == "Identifier":
                    if fn_expr.name in ("require", "assert"):
                        for arg in node.arguments:
                            if self._references_var(arg, var_id, var_name):
                                return True

            # if (success) { ... }
            if node.node_type == "IfStatement":
                cond = node.condition
                if cond and self._references_var(cond, var_id, var_name):
                    return True

        return False

    def _references_var(self, node: ASTNode, var_id: int, var_name: str) -> bool:
        """Check if a node references a specific variable."""
        for child in node.walk():
            if child.node_type == "Identifier":
                if child.referenced_declaration == var_id:
                    return True
                if child.name == var_name:
                    return True
        return False

    def _contains_node(self, tree: ASTNode, target: ASTNode) -> bool:
        """Check if a tree contains a specific node (by source offset)."""
        target_offset = target.get_source_offset()
        for node in tree.walk():
            if node.get_source_offset() == target_offset and node.node_type == target.node_type:
                return True
        return False
