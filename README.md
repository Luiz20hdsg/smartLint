# SmartLint 🔍

**Static detection of insecure patterns in Solidity smart contracts, inspired by Move's resource model.**

SmartLint is a research tool that analyzes Solidity smart contracts by operating on the AST produced by the Solidity compiler (`solc`). It implements three security checkers, each inspired by a safety guarantee that the [Move language](https://github.com/move-language/move) provides natively. Each finding is annotated with the corresponding Move guarantee that would structurally prevent the detected vulnerability class.

> 📄 **Paper:** *SmartLint: Static Detection of Insecure Patterns in Solidity Smart Contracts Inspired by Move's Resource Model* — submitted to **SBLP 2026** (Simpósio Brasileiro de Linguagens de Programação).

---

## Features

| Checker | Vulnerability | Move Guarantee | Severity |
|---------|---------------|---------------|----------|
| **CEI Checker** | Checks-Effects-Interactions violations (reentrancy risk) | Resource locking — no cross-module re-entry | HIGH |
| **Access Control** | Unprotected sensitive operations (`selfdestruct`, `delegatecall`, etc.) | Capability-based access — authority as owned object | CRITICAL/HIGH |
| **Unchecked Call** | Low-level calls with unchecked return values | Mandatory error handling — abort semantics | MEDIUM |

- **Zero external dependencies** — only requires Python 3 and `solc`
- **~1,500 lines** of clean, auditable Python code
- **Two output formats:** colored CLI text and structured JSON
- **Move annotations** on every finding for educational value

---

## Quick Start

### Requirements

- Python 3.8+
- Solidity compiler (`solc`) 0.8.x

### Installation

```bash
git clone https://github.com/Luiz20hdsg/smartLint.git
cd smartLint

# Install solc (macOS)
brew install solidity
# Or via solc-select
pip install solc-select && solc-select install 0.8.28 && solc-select use 0.8.28
```

### Usage

```bash
# Analyze a single contract
python -m smartlint analyze contract.sol

# Analyze a directory
python -m smartlint analyze test_contracts/

# JSON output
python -m smartlint analyze test_contracts/ --format json

# Save to file
python -m smartlint analyze test_contracts/ --format json --output results.json
```

### Example Output

```
🔍 SmartLint — Solidity Static Analyzer (Move-Inspired)
═══════════════════════════════════════════════════════

📄 vulnerable_bank.sol
  ⚠ [HIGH] CEI Violation in withdraw()
    State variable modified after external call (line 28)
    💡 Move: Resource model ensures state changes complete
       before any cross-module interactions occur.
```

---

## Security Checkers

### 1. CEI Violation Detector
Detects functions that violate the Checks-Effects-Interactions pattern by performing external calls before completing state modifications. This is the primary vulnerability enabling **reentrancy attacks**.

### 2. Access Control Analyzer
Identifies `public`/`external` functions that perform privileged operations without access control (modifiers like `onlyOwner` or `require(msg.sender == ...)` checks).

### 3. Unchecked External Call Detector
Flags low-level calls (`call`, `delegatecall`, `staticcall`, `send`) whose boolean return values are not verified via `require`, `assert`, or `if` statements.

---

## Test Suite

The repository includes 6 test contracts with known ground truth:

| Contract | Findings | Description |
|----------|----------|-------------|
| `secure_bank.sol` | 0 | Correct CEI pattern |
| `secure_access.sol` | 0 | Proper access control |
| `vulnerable_bank.sol` | 2 | CEI violations |
| `vulnerable_access.sol` | 4 | Missing access control |
| `vulnerable_unchecked.sol` | 8 | Unchecked calls + missing AC |
| `combined_vulnerable.sol` | 5 | All three violation types |

**Result:** 19 TP, 0 FP, 0 FN → **100% precision, 100% recall**

```bash
# Run on all test contracts
python -m smartlint analyze test_contracts/
```

---

## Project Structure

```
smartlint/
├── smartlint/
│   ├── __init__.py          # Package init, version
│   ├── __main__.py          # CLI entry point
│   ├── models.py            # Finding, Severity, Move guarantees
│   ├── ast_parser.py        # solc AST compilation & parsing
│   ├── analyzer.py          # Main analysis orchestrator
│   └── checkers/
│       ├── base.py          # BaseChecker abstract class
│       ├── cei_checker.py   # CEI violation detector
│       ├── access_control_checker.py  # Access control analyzer
│       └── unchecked_call_checker.py  # Unchecked call detector
├── test_contracts/          # 6 Solidity test contracts
├── USAGE.md                 # Detailed usage documentation
├── README.md                # This file
└── requirements.txt         # Python dependencies
```

---

## License

MIT License

---

## Citation

If you use SmartLint in your research, please cite:

```bibtex
@inproceedings{smartlint2026,
  title={SmartLint: Static Detection of Insecure Patterns in Solidity Smart Contracts Inspired by Move's Resource Model},
  author={Anonymous},
  booktitle={XXX Simpósio Brasileiro de Linguagens de Programação (SBLP)},
  year={2026}
}
```
