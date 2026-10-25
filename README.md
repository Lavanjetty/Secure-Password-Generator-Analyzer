# Secure Password Generator & Analyzer

Advanced educational cybersecurity project implemented as a Python command-line application.

## Features
- Cryptographically secure password generation using Python's `secrets` module.
- Configurable length (8–128), character sets, and ambiguous-character exclusion.
- Local password analysis: length, character categories, predictable patterns, repeated characters, and recommendations.
- Assumption-based theoretical entropy estimate.
- Optional `zxcvbn` pattern-aware strength estimator.
- Unit tests with `unittest`.
- No database, logging, network calls, or password storage.

## Requirements
- Python 3.10 or later
- Windows 10/11 and VS Code recommended
- Optional dependency `zxcvbn` (installed from `requirements.txt`)

## Run on Windows / VS Code
1. Extract this project folder.
2. Open the folder in VS Code.
3. Open Terminal → New Terminal.
4. Create a virtual environment:
   ```powershell
   py -m venv .venv
   ```
5. Activate it in PowerShell:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, use Command Prompt terminal and run:
   ```bat
   .venv\Scripts\activate.bat
   ```
6. Install optional dependency:
   ```powershell
   python -m pip install -r requirements.txt
   ```
7. Run:
   ```powershell
   python main.py
   ```
8. Run tests:
   ```powershell
   python -m unittest discover -s tests -v
   ```

If `py` is not recognized, use the full path to the Python executable or select the interpreter via `Ctrl+Shift+P` → `Python: Select Interpreter`.

## Project structure
```text
secure_password_generator_analyzer/
├── main.py
├── password_analyzer.py
├── requirements.txt
├── README.md
├── PROJECT_REPORT.md
├── tests/
│   └── test_password_analyzer.py
└── docs/
    ├── architecture.mmd
    └── presentation_outline.md
```

## Security limitations
- This is a learning/demo tool, not a professionally audited password product.
- The custom score is heuristic. Character-pool entropy assumes uniform independent selection and can substantially overstate the strength of human-chosen passwords.
- `zxcvbn` is a useful guessability estimator but is not a guarantee and may not include every breach or attacker strategy.
- Crack-time estimates depend on assumed attacker hardware, hash algorithm, and rate. They are illustrative only.
- The program does not store or transmit passwords, but terminal history, screen capture, clipboard managers, malware, debuggers, and process memory may expose them.
- Python strings cannot be reliably zeroized from memory.
- Do not use this project to store credentials; use a reputable password manager for real accounts.
- A generated password is only as safe as the method used to store and use it. Never reuse passwords.

## Academic integrity / demonstration
Explain the difference between a CSPRNG (`secrets`) and a general-purpose PRNG, the distinction between entropy and guessability, and why local-only processing reduces exposure but does not eliminate endpoint risk.
