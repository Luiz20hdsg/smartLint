"""
Solidity AST Parser.

Parses the JSON AST output from solc --ast-compact-json and provides
utilities for traversing the AST to find relevant nodes.
"""

import json
import subprocess
import os
import shutil
import tempfile
from typing import Optional


def _find_solc() -> str:
    """Find the solc binary. Check common locations."""
    # 1. Check PATH
    solc_path = shutil.which("solc")
    if solc_path:
        return solc_path

    # 2. Check common locations
    candidates = [
        "/tmp/smartlint-bin/solc",
        "/usr/local/bin/solc",
        os.path.expanduser("~/.solc-select/artifacts/solc-0.8.28/solc-0.8.28"),
        os.path.expanduser("~/.solc-select/artifacts/solc-0.8.20/solc-0.8.20"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return "solc"  # Fall back to hoping it's in PATH


class ASTNode:
    """Wrapper around a Solidity AST JSON node for easier traversal."""

    def __init__(self, data: dict, source_code: str = ""):
        self._data = data
        self._source_code = source_code

    @property
    def node_type(self) -> str:
        return self._data.get("nodeType", "")

    @property
    def id(self) -> int:
        return self._data.get("id", -1)

    @property
    def name(self) -> str:
        return self._data.get("name", "")

    @property
    def src(self) -> str:
        return self._data.get("src", "")

    @property
    def visibility(self) -> str:
        return self._data.get("visibility", "")

    @property
    def state_mutability(self) -> str:
        return self._data.get("stateMutability", "")

    @property
    def kind(self) -> str:
        return self._data.get("kind", "")

    @property
    def operator(self) -> str:
        return self._data.get("operator", "")

    @property
    def modifiers(self) -> list["ASTNode"]:
        mods = self._data.get("modifiers", [])
        return [ASTNode(m, self._source_code) for m in mods]

    @property
    def body(self) -> Optional["ASTNode"]:
        b = self._data.get("body")
        if b:
            return ASTNode(b, self._source_code)
        return None

    @property
    def expression(self) -> Optional["ASTNode"]:
        e = self._data.get("expression")
        if e:
            return ASTNode(e, self._source_code)
        return None

    @property
    def left_hand_side(self) -> Optional["ASTNode"]:
        lhs = self._data.get("leftHandSide")
        if lhs:
            return ASTNode(lhs, self._source_code)
        return None

    @property
    def right_hand_side(self) -> Optional["ASTNode"]:
        rhs = self._data.get("rightHandSide")
        if rhs:
            return ASTNode(rhs, self._source_code)
        return None

    @property
    def arguments(self) -> list["ASTNode"]:
        args = self._data.get("arguments", []) or []
        return [ASTNode(a, self._source_code) for a in args]

    @property
    def statements(self) -> list["ASTNode"]:
        stmts = self._data.get("statements", []) or []
        return [ASTNode(s, self._source_code) for s in stmts]

    @property
    def members(self) -> list["ASTNode"]:
        return self._data.get("members", [])

    @property
    def type_string(self) -> str:
        td = self._data.get("typeDescriptions", {})
        return td.get("typeString", "")

    @property
    def type_identifier(self) -> str:
        td = self._data.get("typeDescriptions", {})
        return td.get("typeIdentifier", "")

    @property
    def member_name(self) -> str:
        return self._data.get("memberName", "")

    @property
    def referenced_declaration(self) -> Optional[int]:
        return self._data.get("referencedDeclaration")

    @property
    def state_variable(self) -> bool:
        return self._data.get("stateVariable", False)

    @property
    def is_lvalue(self) -> bool:
        return self._data.get("isLValue", False)

    @property
    def modifier_name(self) -> Optional["ASTNode"]:
        mn = self._data.get("modifierName")
        if mn:
            return ASTNode(mn, self._source_code)
        return None

    @property
    def initial_value(self) -> Optional["ASTNode"]:
        iv = self._data.get("initialValue")
        if iv:
            return ASTNode(iv, self._source_code)
        return None

    @property
    def condition(self) -> Optional["ASTNode"]:
        c = self._data.get("condition")
        if c:
            return ASTNode(c, self._source_code)
        return None

    @property
    def true_body(self) -> Optional["ASTNode"]:
        tb = self._data.get("trueBody")
        if tb:
            return ASTNode(tb, self._source_code)
        return None

    @property
    def false_body(self) -> Optional["ASTNode"]:
        fb = self._data.get("falseBody")
        if fb:
            return ASTNode(fb, self._source_code)
        return None

    @property
    def declarations(self) -> list["ASTNode"]:
        decls = self._data.get("declarations", []) or []
        return [ASTNode(d, self._source_code) for d in decls if d is not None]

    @property
    def raw(self) -> dict:
        return self._data

    def get_source_offset(self) -> int:
        """Get the byte offset of this node in the source code."""
        src = self.src
        if src:
            parts = src.split(":")
            if len(parts) >= 1:
                try:
                    return int(parts[0])
                except ValueError:
                    pass
        return 0

    def get_source_length(self) -> int:
        """Get the byte length of this node in the source code."""
        src = self.src
        if src:
            parts = src.split(":")
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
        return 0

    def get_line_number(self) -> int:
        """Get the line number of this node in the source code."""
        if not self._source_code:
            return 0
        offset = self.get_source_offset()
        return self._source_code[:offset].count("\n") + 1

    def get_source_text(self) -> str:
        """Get the source text of this node."""
        if not self._source_code:
            return ""
        offset = self.get_source_offset()
        length = self.get_source_length()
        return self._source_code[offset:offset + length]

    def children(self) -> list["ASTNode"]:
        """Get all child nodes."""
        result = []
        for key, value in self._data.items():
            if isinstance(value, dict) and "nodeType" in value:
                result.append(ASTNode(value, self._source_code))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "nodeType" in item:
                        result.append(ASTNode(item, self._source_code))
        return result

    def walk(self):
        """Recursively walk all descendant nodes (depth-first)."""
        yield self
        for child in self.children():
            yield from child.walk()

    def find_all(self, node_type: str) -> list["ASTNode"]:
        """Find all descendant nodes of a given type."""
        return [n for n in self.walk() if n.node_type == node_type]

    def find_first(self, node_type: str) -> Optional["ASTNode"]:
        """Find the first descendant node of a given type."""
        for n in self.walk():
            if n.node_type == node_type:
                return n
        return None

    def __repr__(self):
        name = f" '{self.name}'" if self.name else ""
        return f"<ASTNode {self.node_type}{name}>"


def compile_and_get_ast(file_path: str) -> tuple[Optional[dict], Optional[str], str]:
    """
    Compile a Solidity file and return its AST.

    Returns:
        (ast_dict, error_message, source_code)
    """
    if not os.path.exists(file_path):
        return None, f"File not found: {file_path}", ""

    # Read source code for line number resolution
    with open(file_path, "r") as f:
        source_code = f.read()

    try:
        solc_bin = _find_solc()
        result = subprocess.run(
            [solc_bin, "--ast-compact-json", file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            # Try to extract useful error message
            error_msg = result.stderr.strip()
            if not error_msg:
                error_msg = result.stdout.strip()
            return None, f"Compilation error: {error_msg}", source_code

        # Parse the JSON AST from stdout
        # solc outputs: ======= file.sol =======\nJSON\n
        output = result.stdout
        ast_json = _extract_ast_json(output)

        if ast_json is None:
            return None, "Failed to extract AST JSON from compiler output", source_code

        return ast_json, None, source_code

    except FileNotFoundError:
        return None, (
            "solc compiler not found. Install it with:\n"
            "  brew install solidity\n"
            "  OR\n"
            "  pip install solc-select && solc-select install 0.8.20 && solc-select use 0.8.20"
        ), source_code
    except subprocess.TimeoutExpired:
        return None, "Compilation timed out (30s)", source_code
    except Exception as e:
        return None, f"Unexpected error: {e}", source_code


def compile_and_get_ast_combined(file_path: str) -> tuple[Optional[dict], Optional[str], str]:
    """
    Compile using --combined-json ast for better compatibility.

    Returns:
        (ast_dict, error_message, source_code)
    """
    if not os.path.exists(file_path):
        return None, f"File not found: {file_path}", ""

    with open(file_path, "r") as f:
        source_code = f.read()

    try:
        solc_bin = _find_solc()
        result = subprocess.run(
            [solc_bin, "--combined-json", "ast", file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            return None, f"Compilation error: {error_msg}", source_code

        combined = json.loads(result.stdout)
        # Extract AST for the file
        sources = combined.get("sources", {})
        for src_name, src_data in sources.items():
            ast_data = src_data.get("AST") or src_data.get("ast")
            if ast_data:
                return ast_data, None, source_code

        return None, "No AST found in combined JSON output", source_code

    except FileNotFoundError:
        return None, (
            "solc compiler not found. Install it with:\n"
            "  brew install solidity\n"
            "  OR\n"
            "  pip install solc-select && solc-select install 0.8.20 && solc-select use 0.8.20"
        ), source_code
    except json.JSONDecodeError as e:
        return None, f"Failed to parse JSON: {e}", source_code
    except subprocess.TimeoutExpired:
        return None, "Compilation timed out (30s)", source_code
    except Exception as e:
        return None, f"Unexpected error: {e}", source_code


def _extract_ast_json(output: str) -> Optional[dict]:
    """Extract JSON AST from solc output which may have header lines."""
    lines = output.strip().split("\n")

    # Find the start of JSON (first line starting with '{')
    json_start = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("{"):
            json_start = i
            break

    if json_start == -1:
        return None

    json_text = "\n".join(lines[json_start:])

    # There may be multiple JSON objects (one per source file)
    # We want the first complete one
    try:
        return json.loads(json_text)
    except json.JSONDecodeError:
        # Try to find balanced braces
        depth = 0
        end_idx = 0
        for i, ch in enumerate(json_text):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_idx = i + 1
                    break
        if end_idx > 0:
            try:
                return json.loads(json_text[:end_idx])
            except json.JSONDecodeError:
                pass
    return None


def parse_ast(file_path: str) -> tuple[Optional[ASTNode], Optional[str], str]:
    """
    Parse a Solidity file and return its AST as an ASTNode tree.

    Tries --combined-json first (more reliable), falls back to --ast-compact-json.

    Returns:
        (root_node, error_message, source_code)
    """
    # Try combined JSON first
    ast_dict, error, source_code = compile_and_get_ast_combined(file_path)

    if ast_dict is not None:
        return ASTNode(ast_dict, source_code), None, source_code

    # Fall back to --ast-compact-json
    ast_dict2, error2, source_code2 = compile_and_get_ast(file_path)
    if ast_dict2 is not None:
        return ASTNode(ast_dict2, source_code2), None, source_code2

    # Return the first error that was produced
    return None, error or error2, source_code or source_code2
