# File Integrity Checker

Project URL: https://github.com/Admin/file-integrity-checker

A small CLI tool to verify log file integrity using SHA-256 hashes. It stores baseline hashes and detects tampering, missing files, and new files in monitored directories.

## Features

- `check` verifies files against a stored baseline
- `init` creates or refreshes the baseline
- `list` shows stored hashes
- `purge` removes baseline entries
- `log` shows recent audit activity

## Installation

```bash
python fic.py --help