"""
CEI Checker — Checks-Effects-Interactions violation detector.

Detects functions where external calls (Interactions) occur before
state variable modifications (Effects), which creates reentrancy risk.

In Move, this vulnerability class is structurally eliminated by the
resource model and the absence of arbitrary external calls.
"""

from ..ast_parser import ASTNode
from ..models import Finding, Severity, CheckerType
from .base import BaseChecker


class CEIChecker(BaseChecker):
    """Detects violations of the Checks-Effects-Interactions pattern."""

    # Known external call patterns
    EXTERNAL_CALL_MEMBERS = {"call", "delegatecall", "staticcall", "transfer", "send"}

    def check(self, root: ASTNode) -> list[Finding]:
        findings = []

        for contract in root.find_all("ContractDefinition"):
            # Collect state variable declaration IDs for this contract
            state_var_ids = self._collect_state_var_ids(contract)

            for func in contract.find_all("FunctionDefinition"):
                if func.body is None:
                    continue

                func_findings = self._check_function(
                    func, state_var_ids, contract.name
                )
                findings.extend(func_findings)

        return findings

    def _collect_state_var_ids(self, contract: ASTNode) -> set[int]:
        """Collect IDs of all state variable declarations in the contract."""
        ids = set()
        for node in contract.children():
            if node.node_type == "VariableDeclaration" and node.state_variable:
                ids.add(node.id)
        return ids

    def _check_function(
        self, func: ASTNode, state_var_ids: set[int], contract_name: str
    ) -> list[Finding]:
        """Check a single function for CEI violations."""
        findings = []

        # Collect all external calls and state modifications with their positions
        external_calls = []
        state_mods = []

        self._collect_operations(func.body, state_var_ids, external_calls, state_mods)

        # Check: is there any state modification AFTER an external call?
        for call_node, call_offset in external_calls:
            for mod_node, mod_offset in state_mods:
                if mod_offset > call_offset:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        checker=CheckerType.CEI,
                        title="Checks-Effects-Interactions Violation",
                        message=(
                            f"State variable is modified (line {mod_node.get_line_number()}) "
                            f"after an external call (line {call_node.get_line_number()}). "
                            f"This violates the CEI pattern and may enable reentrancy attacks. "
                            f"Move all state changes before the external call."
                        ),
                        location=self._make_location(call_node),
                        function_name=func.name,
                        contract_name=contract_name,
                    ))
                    # Only report once per external call
                    break

        return findings

    def _collect_operations(
        self,
        node: ASTNode,
        state_var_ids: set[int],
        external_calls: list,
        state_mods: list,
    ):
        """
        Walk the function body and collect external calls and state modifications
        with their source offsets.
        """
        for child in node.walk():
            # Check for external calls
            if self._is_external_call(child):
                external_calls.append((child, child.get_source_offset()))

            # Check for state variable modifications
            if self._is_state_modification(child, state_var_ids):
                state_mods.append((child, child.get_source_offset()))

    def _is_external_call(self, node: ASTNode) -> bool:
        """Determine if a node represents an external call."""
        if node.node_type != "FunctionCall":
            return False

        expr = node.expression
        if expr is None:
            return False

        # Pattern: address.call{value: ...}(""), address.transfer(...), address.send(...)
        if expr.node_type == "MemberAccess":
            member = expr.member_name
            if member in self.EXTERNAL_CALL_MEMBERS:
                return True

        # Pattern: FunctionCallOptions wrapping a member access (e.g., .call{value: x})
        if expr.node_type == "FunctionCallOptions":
            inner = expr.expression
            if inner and inner.node_type == "MemberAccess":
                if inner.member_name in self.EXTERNAL_CALL_MEMBERS:
                    return True

        # Check for calls to external contract functions
        # (type string contains "contract" and it's an external call)
        if expr.node_type == "MemberAccess":
            type_str = expr.type_string
            if "function" in type_str and "external" in type_str:
                return True

        return False

    def _is_state_modification(self, node: ASTNode, state_var_ids: set[int]) -> bool:
        """Determine if a node modifies a state variable."""
        # Direct assignment: stateVar = ...
        if node.node_type == "Assignment":
            lhs = node.left_hand_side
            if lhs and self._references_state_var(lhs, state_var_ids):
                return True

        # Unary operations: stateVar++ / stateVar-- / ++stateVar / --stateVar / delete stateVar
        if node.node_type == "UnaryOperation":
            op = node.operator
            if op in ("++", "--", "delete"):
                for sub in node.children():
                    if self._references_state_var(sub, state_var_ids):
                        return True

        return False

    def _references_state_var(self, node: ASTNode, state_var_ids: set[int]) -> bool:
        """Check if a node (or its children) references a state variable."""
        # Direct identifier reference
        if node.node_type == "Identifier":
            ref_id = node.referenced_declaration
            if ref_id and ref_id in state_var_ids:
                return True

        # Indexed access: mapping[key] = value (e.g., balances[msg.sender] = 0)
        if node.node_type == "IndexAccess":
            base = node.raw.get("baseExpression")
            if base and isinstance(base, dict):
                base_node = ASTNode(base, self.source_code)
                if base_node.node_type == "Identifier":
                    ref_id = base_node.referenced_declaration
                    if ref_id and ref_id in state_var_ids:
                        return True

        # Member access: struct.field (check if base is state var)
        if node.node_type == "MemberAccess":
            inner_expr = node.expression
            if inner_expr:
                return self._references_state_var(inner_expr, state_var_ids)

        return False
