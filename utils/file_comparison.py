#!/usr/bin/env python3
"""File Comparison Utility

Compare two text files and display differences in unified diff format.
Can be used as a library or standalone CLI tool.

Exit codes:
 - 0: files are identical
 - 1: files differ
 - 2: error (file not found, read error, invalid arguments)

Examples:
    # CLI usage
    python utils/file_comparison.py file1.txt file2.txt
    python utils/file_comparison.py file1.txt file2.txt --context 5

    # Library usage
    from utils.file_comparison import files_are_identical, compare_files_unified

    identical, msg = files_are_identical('file1.txt', 'file2.txt')
    if not identical:
        diff = compare_files_unified('file1.txt', 'file2.txt')
        for line in diff:
            print(line)
"""
import argparse
import os
import sys
from difflib import unified_diff
from typing import List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger_aws_toolkit


logger = logger_aws_toolkit()


def read_file_lines(file_path: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """Read file into list of lines with error handling.

    Args:
        file_path: Path to file to read

    Returns:
        Tuple of (lines_list, error_message)
        - If successful: (list of lines, None)
        - If error: (None, error message string)
    """
    logger.debug(f'Reading file: {file_path}')

    if not os.path.exists(file_path):
        error_msg = f'File not found: {file_path}'
        logger.error(error_msg)
        return None, error_msg

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        logger.debug(f'Successfully read {len(lines)} lines from {file_path}')
        return lines, None
    except PermissionError:
        error_msg = f'Permission denied: {file_path}'
        logger.error(error_msg)
        return None, error_msg
    except UnicodeDecodeError:
        logger.warning(f'UTF-8 decode failed for {file_path}, trying latin-1 encoding')
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                lines = f.readlines()
            logger.debug(f'Successfully read {len(lines)} lines from {file_path} using latin-1')
            return lines, None
        except Exception as e:
            error_msg = f'Unable to decode file {file_path}: {e}'
            logger.error(error_msg)
            return None, error_msg
    except Exception as e:
        error_msg = f'Error reading file {file_path}: {e}'
        logger.error(error_msg)
        return None, error_msg


def files_are_identical(file1: str, file2: str) -> Tuple[bool, str]:
    """Quick check if two files are identical.

    Args:
        file1: Path to first file
        file2: Path to second file

    Returns:
        Tuple of (are_identical: bool, message: str)
    """
    logger.info(f'Comparing files: {file1} and {file2}')

    # Check if both files exist
    if not os.path.exists(file1):
        return False, f'File not found: {file1}'
    if not os.path.exists(file2):
        return False, f'File not found: {file2}'

    # Quick size comparison
    size1 = os.path.getsize(file1)
    size2 = os.path.getsize(file2)

    if size1 != size2:
        logger.debug(f'Files differ in size: {size1} vs {size2}')
        return False, f'Files differ (different sizes: {size1} vs {size2} bytes)'

    # Read and compare content
    lines1, error1 = read_file_lines(file1)
    if error1:
        return False, error1

    lines2, error2 = read_file_lines(file2)
    if error2:
        return False, error2

    if lines1 == lines2:
        logger.info('Files are identical')
        return True, 'Files are identical'
    else:
        logger.info('Files differ in content')
        return False, 'Files differ'


def compare_files_unified(file1: str, file2: str, context_lines: int = 3) -> List[str]:
    """Generate unified diff output for two files.

    Args:
        file1: Path to first file
        file2: Path to second file
        context_lines: Number of context lines to show (default: 3)

    Returns:
        List of diff lines in unified diff format
        Empty list if files are identical or on error
    """
    logger.debug(f'Generating unified diff with {context_lines} context lines')

    lines1, error1 = read_file_lines(file1)
    if error1:
        logger.error(f'Cannot read file1: {error1}')
        return []

    lines2, error2 = read_file_lines(file2)
    if error2:
        logger.error(f'Cannot read file2: {error2}')
        return []

    # Generate unified diff
    diff = unified_diff(
        lines1,
        lines2,
        fromfile=file1,
        tofile=file2,
        n=context_lines
    )

    diff_lines = list(diff)
    logger.debug(f'Generated {len(diff_lines)} diff lines')

    return diff_lines


def main() -> int:
    """Main function for CLI usage.

    Returns:
        Exit code (0=identical, 1=differ, 2=error)
    """
    parser = argparse.ArgumentParser(
        description='Compare two text files and show differences',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare two files (unified diff)
  %(prog)s file1.txt file2.txt

  # Show more context lines
  %(prog)s file1.txt file2.txt --context 5

  # Quiet mode (only exit code)
  %(prog)s file1.txt file2.txt --quiet

Exit codes:
  0 - Files are identical
  1 - Files differ
  2 - Error (file not found, read error)
        """
    )

    parser.add_argument('file1', help='First file to compare')
    parser.add_argument('file2', help='Second file to compare')
    parser.add_argument('--context', '-c', type=int, default=3,
                       help='Number of context lines (default: 3)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Quiet mode: only report via exit code')

    args = parser.parse_args()

    # Validate arguments
    if args.context < 0:
        print('ERROR: Context lines must be non-negative', file=sys.stderr)
        logger.error(f'Invalid context argument: {args.context}')
        return 2

    logger.info(f'Starting file comparison: {args.file1} vs {args.file2}')

    # Quick check if files are identical
    identical, msg = files_are_identical(args.file1, args.file2)

    # Handle errors
    if 'not found' in msg.lower() or 'error' in msg.lower():
        if not args.quiet:
            print(f'ERROR: {msg}', file=sys.stderr)
        return 2

    # If identical
    if identical:
        if not args.quiet:
            print('Files are identical')
        logger.info('Comparison complete: files are identical')
        return 0

    # Files differ - show diff
    if not args.quiet:
        diff_lines = compare_files_unified(args.file1, args.file2, args.context)
        if diff_lines:
            for line in diff_lines:
                # Print without extra newline since diff lines already have them
                print(line, end='')
        else:
            print('Files differ but could not generate diff', file=sys.stderr)
            return 2

    logger.info('Comparison complete: files differ')
    return 1


if __name__ == '__main__':
    sys.exit(main())
