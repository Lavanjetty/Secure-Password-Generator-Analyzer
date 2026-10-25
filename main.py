from __future__ import annotations

import getpass
import secrets
import string
import sys

from password_analyzer import analyze_password, format_analysis, generate_password

BANNER = r"""
  ____                      ____                               
 / ___|  ___  ___ _   _ _ __|  _ \ __ _ ___ _____      _____  _ __ __| |
 \___ \ / _ \/ __| | | | '__| |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` |
  ___) |  __/ (__| |_| | |  |  __/ (_| \__ \__ \\ V  V / (_) | | | (_| |
 |____/ \___|\___|\__,_|_|  |_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|
                         GENERATOR & ANALYZER
"""


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        answer = input(f"{prompt} {suffix}: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}: return True
        if answer in {"n", "no"}: return False
        print("Please enter y or n.")


def generate_flow() -> None:
    try:
        raw_length = input("Password length (8-128, default 20): ").strip()
        length = int(raw_length) if raw_length else 20
        lower = ask_yes_no("Include lowercase letters?", True)
        upper = ask_yes_no("Include uppercase letters?", True)
        digits = ask_yes_no("Include digits?", True)
        symbols = ask_yes_no("Include symbols?", True)
        ambiguous = ask_yes_no("Avoid ambiguous characters such as O/0/I/l/1?", False)
        password = generate_password(length, lower, upper, digits, symbols, ambiguous)
        print("\nGenerated password (shown once on screen):")
        print("-" * 56)
        print(password)
        print("-" * 56)
        print("Tip: save it directly into a trusted password manager; do not reuse it.")
        if ask_yes_no("Analyze this generated password?", True):
            print(format_analysis(analyze_password(password)))
    except (ValueError, TypeError) as exc:
        print(f"Could not generate password: {exc}")


def analyze_flow() -> None:
    print("Enter a password to analyze. Input is hidden where the terminal supports it.")
    print("Analysis is local; the program does not save or transmit the input.")
    try:
        password = getpass.getpass("Password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return
    try:
        print(format_analysis(analyze_password(password)))
    finally:
        # Python strings cannot be reliably zeroized; do not treat this as memory erasure.
        password = ""


def main() -> None:
    print(BANNER)
    while True:
        print("\n[1] Generate a secure password")
        print("[2] Analyze a password")
        print("[3] Exit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            generate_flow()
        elif choice == "2":
            analyze_flow()
        elif choice == "3":
            print("Exiting. Keep passwords unique and store them safely.")
            break
        else:
            print("Choose 1, 2, or 3.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye.")
        sys.exit(0)
