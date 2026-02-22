# SmartLint — User Documentation

**SmartLint** is a static analysis tool for Solidity smart contracts that detects insecure coding patterns inspired by the safety guarantees of the Move language's resource model.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [analyze](#analyze)
- [Output Formats](#output-formats)
  - [Text (default)](#text-default)
  - [JSON](#json)
- [Checkers](#checkers)
  - [CEI Checker (Reentrancy)](#1-cei-checker-reentrancy)
  - [Access Control Checker](#2-access-control-checker)
  - [Unchecked Call Checker](#3-unchecked-call-checker)
- [Severity Levels](#severity-levels)
- [Exit Codes](#exit-codes)
- [Examples](#examples)

---

## Requirements

| Requirement | Version |
|---|---|
| Python | ≥ 3.10 |
| Solidity Compiler (`solc`) | ≥ 0.8.0 |

SmartLint has **no external Python dependencies**. It uses only the Python standard library.

The `solc` compiler must be accessible either in your system `PATH` or at one of the following locations:
- `/usr/local/bin/solc`
- `/tmp/smartlint-bin/solc`
- `~/.local/bin/solc`

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd smartlint

# Verify solc is available
solc --version
# Expected: solc, the solidity compiler commandline interface
# Version: 0.8.x+commit...

# Run directly (no install needed)
python3 -m smartlint analyze <path>
```

## Quick Start

```bash
# Analyze a single Solidity file
python3 -m smartlint analyze contracts/MyContract.sol

# Analyze all .sol files in a directory
python3 -m smartlint analyze contracts/

# Output results as JSON
python3 -m smartlint analyze contracts/ --format json

# Save JSON results to a file
python3 -m smartlint analyze contracts/ --format json --output results.json
```

---

## Commands

### `analyze`

Analyzes Solidity source files for insecure coding patterns.

**Syntax:**
```
python3 -m smartlint analyze <path> [--format text|json] [--output FILE]
```

**Arguments:**

| Argument | Required | Description |
|---|---|---|
| `path` | Yes | Path to a `.sol` file or a directory containing `.sol` files |
| `--format` | No | Output format: `text` (default) or `json` |
| `--output`, `-o` | No | File path to write JSON output (only with `--format json`) |

**Behavior:**
- When `path` is a file, SmartLint analyzes that single file.
- When `path` is a directory, SmartLint recursively finds and analyzes all `.sol` files.
- Each file is compiled individually using `solc` to produce a JSON AST, which is then traversed by the three checkers.

---

## Output Formats

### Text (default)

The default text output displays a banner, per-file summaries, detailed findings with severity, and Move-inspired educational annotations.

```
╔═══════════════════════════════════════════════════════╗
║  SmartLint v0.1.0                                     ║
║  Static Analysis for Solidity · Inspired by Move      ║
╚═══════════════════════════════════════════════════════╝

  Analyzing: test_contracts/

  ✓ secure_bank.sol: No findings (1 contracts, 3 functions)
  ⚠ vulnerable_bank.sol: 2 finding(s) (1 contracts, 4 functions)
  [1] HIGH — Checks-Effects-Interactions Violation
      Checker:  CEI
      Contract: VulnerableBank
      Function: withdraw
      Location: test_contracts/vulnerable_bank.sol:24
      State variable is modified (line 28) after an external call
      (line 24). This violates the CEI pattern and may enable
      reentrancy attacks.
      💡 Move: In Move, this vulnerability class is structurally
      eliminated: the resource model ensures that state changes are
      completed before any cross-module interactions occur.

═══════════════════════════════════════════════════════
  SUMMARY
═══════════════════════════════════════════════════════
  Files analyzed:     2
  Contracts analyzed: 2
  Functions analyzed: 7
  Total findings:     2

  By Severity:
    HIGH          2

  By Checker:
    CEI           2
```

### JSON

The `--format json` flag produces a machine-readable JSON output suitable for CI/CD integration and automated processing.

```bash
python3 -m smartlint analyze contracts/ --format json
```

**JSON Schema:**
```json
{
  "results": [
    {
      "file": "path/to/contract.sol",
      "contracts_analyzed": 1,
      "functions_analyzed": 4,
      "total_findings": 2,
      "findings": [
        {
          "severity": "HIGH",
          "checker": "CEI",
          "title": "Checks-Effects-Interactions Violation",
          "message": "State variable is modified (line 28) after...",
          "location": "path/to/contract.sol:24",
          "function": "withdraw",
          "contract": "VulnerableBank",
          "move_guarantee": "In Move, this vulnerability class..."
        }
      ]
    }
  ],
  "summary": {
    "files_analyzed": 1,
    "total_findings": 2
  }
}
```

---

## Checkers

SmartLint implements three security checkers, each inspired by a guarantee that the Move language provides natively through its resource model.

### 1. CEI Checker (Reentrancy)

**Identifier:** `CEI`

**Description:** Detects violations of the Checks-Effects-Interactions pattern. A violation occurs when a function performs an external call (Interaction) before completing all state variable modifications (Effects), creating a reentrancy vulnerability.

**Detected external calls:**
- `address.call{value: ...}(...)` — low-level call with value transfer
- `address.transfer(...)` — transfer of Ether
- `address.send(...)` — send Ether
- `address.delegatecall(...)` — delegate call
- `address.staticcall(...)` — static call

**Detected state modifications:**
- Direct assignment to state variables (`stateVar = ...`)
- Compound assignment to state variables (`stateVar += ...`)
- Index-based assignment to mappings/arrays (`mapping[key] = ...`)
- Member access assignment to structs (`stateVar.field = ...`)

**Severity:** HIGH

**Move guarantee:** In Move, reentrancy is structurally impossible because the execution model does not allow a function to transfer control to arbitrary external code during execution.

**Example — Vulnerable code:**
```solidity
function withdraw() public {
    uint amount = balances[msg.sender];
    require(amount > 0);
    (bool sent, ) = msg.sender.call{value: amount}(""); // Interaction
    require(sent);
    balances[msg.sender] = 0; // Effect AFTER Interaction ← FLAGGED
}
```

### 2. Access Control Checker

**Identifier:** `ACCESS_CONTROL`

**Description:** Detects `public` or `external` functions that perform sensitive operations without adequate access control mechanisms (modifiers or `msg.sender` checks).

**Detected sensitive operations:**
- `selfdestruct(...)` — contract destruction
- `address.delegatecall(...)` — arbitrary code execution
- `address.transfer(...)` / `address.send(...)` / `address.call{value}(...)` — Ether transfers to arbitrary recipients (transfers to `msg.sender` in user-withdrawal patterns are excluded)
- Assignments to owner-like variables (`owner`, `_owner`, `admin`, `_admin`, `governance`)

**Recognized access control mechanisms:**
- Modifiers containing: `onlyOwner`, `onlyAdmin`, `onlyMinter`, `onlyAuthorized`, `onlyRole`, `auth`, `restricted`, or any modifier with `only` in its name
- `require(...)` or `assert(...)` statements that check `msg.sender`

**Severity:** CRITICAL for `selfdestruct` and `delegatecall`; HIGH for other operations.

**Move guarantee:** In Move, access control is enforced through capability resources (`AdminCap`). Possessing the capability resource is the proof of authorization — making unauthorized access a compile-time type error.

**Example — Vulnerable code:**
```solidity
function destroy() public { // No onlyOwner or msg.sender check
    selfdestruct(payable(msg.sender)); // ← FLAGGED (CRITICAL)
}
```

### 3. Unchecked Call Checker

**Identifier:** `UNCHECKED_CALL`

**Description:** Detects low-level calls whose boolean return values are not checked, which can lead to silent failures and inconsistent contract state.

**Detected low-level calls:**
- `address.call(...)` — including `call{value: ...}()`
- `address.delegatecall(...)`
- `address.staticcall(...)`
- `address.send(...)` — returns `bool`

**A return value is considered "checked" if:**
1. It is captured in a `VariableDeclarationStatement` (e.g., `(bool success, ) = ...`) **AND** the variable is subsequently used in a `require`, `assert`, or `if` statement.
2. The call is directly wrapped inside a `require(...)` or `assert(...)`.

**Severity:** MEDIUM

**Move guarantee:** In Move, all operations that may fail must have their results explicitly handled by the type system, preventing silent failures.

**Example — Vulnerable code:**
```solidity
function sendEther(address payable recipient) public {
    recipient.call{value: 1 ether}(""); // Return value discarded ← FLAGGED
}
```

**Example — Safe code (not flagged):**
```solidity
function safeSend(address payable recipient, uint256 amount) public {
    (bool success, ) = recipient.call{value: amount}("");
    require(success, "Transfer failed"); // Return value checked ✓
}
```

---

## Severity Levels

| Level | Color | Description |
|---|---|---|
| **CRITICAL** | 🔴 Red Bold | Immediate risk — contract destruction, arbitrary code execution |
| **HIGH** | 🔴 Red | Significant risk — reentrancy, unprotected Ether transfers |
| **MEDIUM** | 🟡 Yellow | Moderate risk — unchecked return values |
| **LOW** | 🔵 Cyan | Minor issues (reserved for future checkers) |
| **INFO** | ⚪ Dim | Informational (reserved for future checkers) |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Analysis completed with no findings |
| `1` | Analysis completed with one or more findings |

This allows SmartLint to be integrated into CI/CD pipelines:
```bash
python3 -m smartlint analyze contracts/ || echo "Security issues found!"
```

---

## Examples

### Analyze a DeFi protocol
```bash
python3 -m smartlint analyze ./defi-protocol/contracts/
```

### Generate a JSON report for CI
```bash
python3 -m smartlint analyze src/ --format json --output smartlint-report.json
```

### Analyze a single contract
```bash
python3 -m smartlint analyze contracts/Vault.sol
```

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ Solidity     │     │ AST Parser  │     │  Checkers    │     │    Report    │
│ Source (.sol)│────▶│ (solc JSON) │────▶│  (3 modules) │────▶│  Generator   │
└─────────────┘     └─────────────┘     └──────────────┘     └──────────────┘
       │                                       │
       ▼                                       ▼
  solc --combined-json ast           ┌─────────┼─────────┐
                                     │         │         │
                                     ▼         ▼         ▼
                                   CEI     Access    Unchecked
                                  Checker  Control     Call
                                           Checker   Checker
```

SmartLint is implemented in approximately 1,500 lines of Python 3 with no external dependencies beyond the Solidity compiler.
