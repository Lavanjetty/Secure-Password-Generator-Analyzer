# Project Report: Secure Password Generator & Analyzer

## 1. Abstract
This project implements a command-line cybersecurity utility that generates random passwords with Python's cryptographically secure `secrets` API and analyzes entered passwords for basic structural weaknesses. It reports password length, observed character classes, a theoretical entropy estimate under explicit assumptions, rule-based findings, and optional `zxcvbn` guessability feedback. The program runs locally and does not intentionally persist or transmit password input.

## 2. Problem statement
Weak, reused, and predictable passwords remain vulnerable to guessing and credential-stuffing attacks. Users need a tool that can create unique passwords and explain common weaknesses without sending secrets to a third-party website.

## 3. Objectives
- Generate configurable random passwords using a cryptographically secure source.
- Guarantee at least one character from every selected character category.
- Identify common patterns and repeated sequences.
- Explain theoretical entropy and its assumptions.
- Provide actionable recommendations and automated tests.
- Keep the default workflow local and storage-free.

## 4. Scope
The application is a local educational CLI. It does not authenticate users, store a vault, query breach databases, or claim to prove password security. No password is intentionally written to a file or sent over a network.

## 5. Tools and technologies
- Python 3.10+
- `secrets`, `string`, `math`, `re`, `getpass`, `unittest`
- Optional `zxcvbn` package for pattern-aware guessability estimation

## 6. Architecture
The CLI receives a generation or analysis request. The generator builds the selected character pool, chooses at least one character from each selected category, fills the remaining positions using `secrets.choice`, and securely shuffles the result. The analyzer checks categories and simple patterns, calculates an assumption-based entropy estimate, and optionally invokes `zxcvbn`. Results are rendered in the terminal. There is no database layer.

## 7. Algorithms
### Password generation
1. Validate length and selected character categories.
2. Build character pools.
3. Select one secure random character from each selected category.
4. Fill remaining positions from the combined pool using `secrets.choice`.
5. Shuffle with `secrets.SystemRandom`.
6. Display the generated value to the user.

### Entropy estimate
The theoretical estimate uses `H = L × log2(N)`, where `L` is password length and `N` is an inferred character-pool size. This only approximates entropy when each character is selected independently and uniformly from that pool. It does not measure a human-chosen password's real unpredictability. Because the generator guarantees category inclusion, its output distribution is not exactly identical to uniformly sampling every position from the combined pool; the estimate should be treated as an explanatory approximation.

### Strength analysis
The custom score combines length thresholds, observed character categories, and pattern warnings. It is intentionally explainable but not a calibrated security metric. Optional `zxcvbn` provides a more pattern-aware estimate, but it too is a model and not a guarantee.

## 8. Security considerations
- Use `secrets`, not `random`, for security-sensitive randomness.
- The app does not log, store, or transmit password inputs by design.
- `getpass` hides interactive input where the terminal supports it.
- Python does not guarantee secure erasure of strings from memory.
- A local program can still be exposed by malware, screen capture, clipboard utilities, terminal recording, or a compromised operating system.
- The custom entropy and strength score can be misleading if interpreted as proof.
- Never reuse passwords; store generated passwords in a reputable password manager.
- Do not use this academic prototype as a production password manager.

## 9. Testing
Tests cover default generation, category inclusion, length bounds, empty category selection, ambiguous-character exclusion, empty input analysis, common password detection, repeated character detection, entropy calculation, and invalid input types. Run using `python -m unittest discover -s tests -v`.

## 10. Expected outcomes
The user can generate unique random passwords and receive transparent feedback about basic weaknesses. The tool demonstrates secure randomness, input validation, local processing, unit testing, and the difference between theoretical entropy and practical guessability.

## 11. Future enhancements
- Optional local breach-list screening using a privacy-preserving workflow.
- Passphrase generation using a vetted word list.
- JSON export of analysis results that explicitly excludes the password itself.
- Accessibility and localization improvements.
- Independent security review and threat modeling before any production use.

## 12. Conclusion
The project provides a practical demonstration of secure random password generation and cautious password analysis. It prioritizes local processing and transparent limitations. Its scores are advisory, not guarantees; good account security also requires uniqueness, multi-factor authentication, and safe password storage.
