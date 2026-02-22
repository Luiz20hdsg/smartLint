"""
Access Control Checker — Detects unprotected sensitive operations.

Detects public/external functions that perform sensitive operations
(selfdestruct, delegatecall, ether transfers, owner changes) without
access control modifiers or msg.sender checks.

In Move, access control is enforced through capability resources (AdminCap),
making unauthorized access a compile-time type error.
"""

from ..ast_parser import ASTNode
from ..models import Finding, Severity, CheckerType
from .base import BaseChecker


class AccessControlChecker(BaseChecker):
    """Detects functions with sensitive operations but no access control."""

    # Modifiers that indicate access control
    ACCESS_CONTROL_MODIFIERS = {
        "onlyowner", "onlyadmin", "onlyminter", "onlyauthorized",
        "onlyrole", "onlygovernance", "onlyoperator", "onlymanager",
        "auth", "restricted", "owneronly", "adminonly",
    }

    # Sensitive function names / member accesses
    SENSITIVE_MEMBERS = {"selfdestruct", "delegatecall", "transfer", "send", "call"}

    # State variable names that suggest ownership
    OWNER_VAR_NAMES = {"owner", "_owner", "admin", "_admin", "governance"}

    def check(self, root: ASTNode) -> list[Finding]:
        findings = []

        for contract in root.find_all("ContractDefinition"):
            # Check if this contract is an interface or library (skip those)
            contract_kind = contract.raw.get("contractKind", "contract")
            if contract_kind in ("interface", "library"):
                continue

            for func in contract.find_all("FunctionDefinition"):
                if func.body is None:
                    continue

                # Only check public and external functions
                vis = func.visibility
                if vis not in ("public", "external"):
                    continue

                # Skip constructors, receive, fallback
                func_kind = func.kind
                if func_kind in ("constructor", "receive", "fallback"):
                    continue

                func_findings = self._check_function(func, contract.name)
                findings.extend(func_findings)

        return findings

    def _check_function(self, func: ASTNode, contract_name: str) -> list[Finding]:
        """Check a single function for missing access control."""
        findings = []

        # 1. Find sensitive operations in the function body
        sensitive_ops = self._find_sensitive_operations(func.body)
        if not sensitive_ops:
            return []

        # 2. Check if function has access control
        if self._has_access_control(func):
            return []

        # 3. Report each unprotected sensitive operation
        for op_type, op_node in sensitive_ops:
            severity = Severity.CRITICAL if op_type in ("selfdestruct", "delegatecall") else Severity.HIGH

            findings.append(Finding(
                severity=severity,
                checker=CheckerType.ACCESS_CONTROL,
                title="Missing Access Control",
                message=(
                    f"Function '{func.name}' performs sensitive operation "
                    f"'{op_type}' (line {op_node.get_line_number()}) "
                    f"without access control. Any external account can call this function."
                ),
                location=self._make_location(func),
                function_name=func.name,
                contract_name=contract_name,
            ))

        return findings

    def _find_sensitive_operations(self, body: ASTNode) -> list[tuple[str, ASTNode]]:
        """Find all sensitive operations in a function body."""
        sensitive = []

        for node in body.walk():
            if node.node_type == "FunctionCall":
                op_name = self._get_sensitive_call_name(node)
                if op_name:
                    # Ether transfers to msg.sender are user-facing withdrawals,
                    # not admin operations — skip them.
                    if op_name.startswith("ether_") and self._is_send_to_msg_sender(node):
                        continue
                    sensitive.append((op_name, node))

            # Detect assignment to owner-like variables
            if node.node_type == "Assignment":
                lhs = node.left_hand_side
                if lhs and self._is_owner_variable(lhs):
                    sensitive.append(("owner_change", node))

        return sensitive

    def _get_sensitive_call_name(self, call_node: ASTNode) -> str | None:
        """Check if a FunctionCall is a sensitive operation, return its name."""
        expr = call_node.expression
        if expr is None:
            return None

        # selfdestruct(addr) — identifier
        if expr.node_type == "Identifier":
            if expr.name in ("selfdestruct", "suicide"):
                return "selfdestruct"

        # addr.transfer(x), addr.send(x), addr.call{value:x}(), addr.delegatecall()
        if expr.node_type == "MemberAccess":
            member = expr.member_name
            if member in self.SENSITIVE_MEMBERS:
                # For transfer/send/call, check if it sends value
                if member in ("transfer", "send"):
                    return f"ether_{member}"
                if member == "delegatecall":
                    return "delegatecall"
                if member == "call":
                    return "ether_call"

        # FunctionCallOptions: .call{value: amount}()
        if expr.node_type == "FunctionCallOptions":
            inner = expr.expression
            if inner and inner.node_type == "MemberAccess":
                if inner.member_name == "call":
                    return "ether_call"

        return None

    def _is_owner_variable(self, node: ASTNode) -> bool:
        """Check if a node references an owner-like variable."""
        if node.node_type == "Identifier":
            return node.name.lower() in self.OWNER_VAR_NAMES

        if node.node_type == "MemberAccess":
            return node.member_name.lower() in self.OWNER_VAR_NAMES

        return False

    def _is_send_to_msg_sender(self, call_node: ASTNode) -> bool:
        """Check if an ether transfer targets msg.sender (user-withdrawal pattern)."""
        expr = call_node.expression

        # addr.transfer(amount) or addr.send(amount) — check addr
        if expr is not None and expr.node_type == "MemberAccess":
            target = expr.expression
            if target is not None:
                return self._is_msg_sender_expr(target)

        # addr.call{value: x}("") — FunctionCallOptions wrapping MemberAccess
        if expr is not None and expr.node_type == "FunctionCallOptions":
            inner = expr.expression
            if inner is not None and inner.node_type == "MemberAccess":
                target = inner.expression
                if target is not None:
                    return self._is_msg_sender_expr(target)

        return False

    def _is_msg_sender_expr(self, node: ASTNode) -> bool:
        """Check if a node is msg.sender or payable(msg.sender)."""
        # Direct: msg.sender
        if (node.node_type == "MemberAccess" and node.member_name == "sender"
                and node.expression is not None
                and node.expression.node_type == "Identifier"
                and node.expression.name == "msg"):
            return True

        # Wrapped: payable(msg.sender)
        if node.node_type == "FunctionCall":
            inner_expr = node.expression
            if (inner_expr is not None
                    and inner_expr.node_type == "ElementaryTypeNameExpression"):
                # payable(...) wrapping msg.sender
                args = node.arguments
                if args and len(args) == 1:
                    return self._is_msg_sender_expr(args[0])

        return False

    def _has_access_control(self, func: ASTNode) -> bool:
        """Check if a function has access control mechanisms."""
        # 1. Check modifiers
        for mod in func.modifiers:
            mod_name_node = mod.modifier_name
            if mod_name_node:
                name = mod_name_node.name.lower()
                if any(acm in name for acm in self.ACCESS_CONTROL_MODIFIERS):
                    return True
                # Also catch any modifier with "only" in its name
                if "only" in name:
                    return True

        # 2. Check for require/assert with msg.sender in the function body
        if func.body:
            for node in func.body.walk():
                if self._is_sender_check(node):
                    return True

        return False

    def _is_sender_check(self, node: ASTNode) -> bool:
        """Check if a node is a require/assert that checks msg.sender."""
        if node.node_type != "FunctionCall":
            return False

        expr = node.expression
        if expr is None:
            return False

        # require(...) or assert(...)
        if expr.node_type == "Identifier" and expr.name in ("require", "assert"):
            # Check if any argument references msg.sender
            for arg in node.arguments:
                if self._contains_msg_sender(arg):
                    return True

        return False

    def _contains_msg_sender(self, node: ASTNode) -> bool:
        """Check if a node tree contains a reference to msg.sender."""
        for child in node.walk():
            if child.node_type == "MemberAccess" and child.member_name == "sender":
                inner = child.expression
                if inner and inner.node_type == "Identifier" and inner.name == "msg":
                    return True
        return False
