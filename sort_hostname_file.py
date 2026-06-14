#!/usr/bin/env python3
"""
Sort a hostname file, preserving comments at the top.

Reads a file with comments and FQDNs, sorts the FQDNs in reverse
hostname component order, and preserves the comments at the top.
"""

import argparse

from common import sort_fqdns


def sort_file(input_path, output_path):
    """
    Sort a hostname file, preserving comments at the top.

    Args:
        input_path: Path to the input file
        output_path: Path to the output file
    """
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    comments = []
    fqdns = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('#'):
            comments.append(stripped)
        else:
            fqdns.append(stripped)

    sorted_fqdns = sort_fqdns(fqdns)

    # Remove consecutive duplicates
    unique_fqdns = []
    for fqdn in sorted_fqdns:
        if not unique_fqdns or fqdn != unique_fqdns[-1]:
            unique_fqdns.append(fqdn)

    with open(output_path, 'w', encoding='utf-8') as f:
        for comment in comments:
            f.write(comment + '\n')
        for fqdn in unique_fqdns:
            f.write(fqdn + '\n')


def main():
    """
    Main function to sort a hostname file.
    """
    parser = argparse.ArgumentParser(
        description='Sort a hostname file with comments.'
    )
    parser.add_argument('input', help='Input file path')
    parser.add_argument('output', nargs='?', help='Output file path (default: overwrite input)')
    args = parser.parse_args()

    output_path = args.output if args.output else args.input
    sort_file(args.input, output_path)


if __name__ == '__main__':
    main()
