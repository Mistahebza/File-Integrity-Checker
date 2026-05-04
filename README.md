# PROJECT

Project URL: https://github.com/Mistahebza/PROJECT
# PROJECT

A command-line tool to verify the integrity of log files using SHA-256 hashing. It detects unauthorized tampering by comparing file hashes against a stored baseline.

## Features

- **Integrity Checking**: Verify files against stored SHA-256 hashes.
- **Baseline Management**: Initialize or re-initialize hash baselines.
- **Audit Logging**: Maintains a secure audit log of all operations.
- **Secure Storage**: Stores hashes in a user-specific directory with restricted permissions.
- **Multi-format Support**: Supports various log file extensions (.log, .txt, .json, .csv, .xml, .out, .err, .trace).

## Installation

1. Ensure Python 3.6+ is installed.
2. Download or clone this repository.
3. Run the script directly: `python fic.py`

## Usage

### Initialize Baseline
Create initial hashes for files in a directory:
```
python fic.py init /path/to/logs
```

### Check Integrity
Verify files against the baseline:
```
python fic.py check /path/to/logs
```

Use `-v` for verbose output:
```
python fic.py check /path/to/logs -v
```

### List Stored Hashes
View all stored baseline entries:
```
python fic.py list
```

### Purge Entries
Remove entries from the store:
```
python fic.py purge /path/to/logs  # Remove for specific path
python fic.py purge                # Remove all entries
```

### View Audit Log
Show recent audit entries:
```
python fic.py log                 # Last 20 entries
python fic.py log -n 50           # Last 50 entries
```

## Storage

- **Hash Store**: `~/.file_integrity/hashes.json` - Stores file hashes and metadata.
- **Audit Log**: `~/.file_integrity/audit.log` - Logs all operations.

The storage directory is created with restricted permissions (owner-only access).

## Security Notes

- Hashes are computed using SHA-256.
- Storage files have restricted permissions to prevent tampering.
- Audit log records all check, init, and purge operations.

## Examples

See the built-in help for more examples:
```
python fic.py --help
```

## License

This project is open-source. Use at your own risk.
