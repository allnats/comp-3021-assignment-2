"""
Secure CSV file writer with input validation and proper error handling.
"""

import csv
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional


def sanitize_cell(value: Any) -> str:
    """
    Sanitize a cell value to prevent CSV injection attacks.
    Removes or escapes potentially dangerous characters that could be
    interpreted as formulas in spreadsheet applications.
    """
    if value is None:
        return ""

    str_value = str(value)

    # Characters that trigger formula interpretation in Excel/Sheets
    dangerous_prefixes = ('=', '+', '-', '@', '\t', '\r', '\n')

    if str_value.startswith(dangerous_prefixes):
        # Prefix with single quote to prevent formula execution
        str_value = "'" + str_value

    return str_value


def validate_filepath(filepath: str) -> Path:
    """
    Validate and sanitize the file path.
    Prevents path traversal attacks and ensures safe file location.
    """
    path = Path(filepath).resolve()

    # Ensure the path doesn't contain suspicious patterns
    if ".." in str(filepath):
        raise ValueError("Path traversal detected in filepath")

    # Ensure it's a .csv file
    if path.suffix.lower() != '.csv':
        raise ValueError("File must have .csv extension")

    return path


def write_csv_secure(
    filepath: str,
    data: List[Dict[str, Any]],
    fieldnames: Optional[List[str]] = None,
    encoding: str = 'utf-8',
    file_permissions: int = 0o644
) -> None:
    """
    Securely write data to a CSV file.

    Args:
        filepath: Path to the output CSV file
        data: List of dictionaries containing the data to write
        fieldnames: Optional list of column names (inferred from data if not provided)
        encoding: File encoding (default: utf-8)
        file_permissions: Unix file permissions (default: 0o644 - owner read/write, others read)

    Raises:
        ValueError: If filepath or data is invalid
        IOError: If file cannot be written
    """
    if not data:
        raise ValueError("Data cannot be empty")

    # Validate filepath
    safe_path = validate_filepath(filepath)

    # Determine fieldnames from data if not provided
    if fieldnames is None:
        fieldnames = list(data[0].keys())

    # Ensure parent directory exists
    safe_path.parent.mkdir(parents=True, exist_ok=True)

    # Sanitize all data
    sanitized_data = []
    for row in data:
        sanitized_row = {
            sanitize_cell(key): sanitize_cell(value)
            for key, value in row.items()
        }
        sanitized_data.append(sanitized_row)

    # Sanitize fieldnames
    safe_fieldnames = [sanitize_cell(f) for f in fieldnames]

    try:
        # Write with secure settings
        with open(safe_path, 'w', newline='', encoding=encoding) as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=safe_fieldnames,
                quoting=csv.QUOTE_ALL,  # Quote all fields for safety
                extrasaction='ignore'
            )
            writer.writeheader()
            writer.writerows(sanitized_data)

        # Set file permissions (Unix-like systems)
        if os.name != 'nt':
            os.chmod(safe_path, file_permissions)

    except (IOError, OSError) as e:
        raise IOError(f"Failed to write CSV file: {e}") from e


def append_csv_secure(
    filepath: str,
    data: List[Dict[str, Any]],
    encoding: str = 'utf-8'
) -> None:
    """
    Securely append data to an existing CSV file.

    Args:
        filepath: Path to the existing CSV file
        data: List of dictionaries to append
        encoding: File encoding (default: utf-8)
    """
    if not data:
        raise ValueError("Data cannot be empty")

    safe_path = validate_filepath(filepath)

    if not safe_path.exists():
        raise FileNotFoundError(f"CSV file does not exist: {filepath}")

    # Read existing fieldnames
    with open(safe_path, 'r', newline='', encoding=encoding) as csvfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames

    if not fieldnames:
        raise ValueError("Existing CSV file has no headers")

    # Sanitize data
    sanitized_data = []
    for row in data:
        sanitized_row = {
            sanitize_cell(key): sanitize_cell(value)
            for key, value in row.items()
        }
        sanitized_data.append(sanitized_row)

    # Append to file
    with open(safe_path, 'a', newline='', encoding=encoding) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_ALL,
            extrasaction='ignore'
        )
        writer.writerows(sanitized_data)


# Example usage
if __name__ == "__main__":
    # Sample data
    sample_data = [
        {"name": "Alice", "email": "alice@example.com", "score": 95},
        {"name": "Bob", "email": "bob@example.com", "score": 87},
        {"name": "=SUM(A1:A10)", "email": "test@example.com", "score": 100},  # Malicious input sanitized
    ]

    # Write to CSV securely
    output_file = "output.csv"

    try:
        write_csv_secure(output_file, sample_data)
        print(f"Successfully wrote data to {output_file}")

        # Append more data
        additional_data = [
            {"name": "Charlie", "email": "charlie@example.com", "score": 92}
        ]
        append_csv_secure(output_file, additional_data)
        print(f"Successfully appended data to {output_file}")

    except (ValueError, IOError) as e:
        print(f"Error: {e}")
