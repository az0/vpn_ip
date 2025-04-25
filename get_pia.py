#!/usr/bin/env python3
"""
Originally by DEVisions
https://github.com/az0/vpn_ip/issues/4
"""

import csv
import requests


def fetch_pia_servers():
    """Fetch PIA servers from GitHub"""
    url = "https://raw.githubusercontent.com/Lars-/PIA-servers/refs/heads/master/export.csv"
    response = requests.get(url, timeout=30)

    if response.status_code != 200:
        print("Failed to fetch data")
        return

    lines = response.text.splitlines()
    reader = csv.reader(lines)

    output_lines = []

    # Skip header
    next(reader, None)

    for row in reader:
        if len(row) < 3:
            print(f"Skipping malformed row: {row}")
            continue  # Skip malformed rows
        ip, country, _timestamp = row[0], row[1], row[2]
        # Omit timestamp to reduce changes.
        formatted_line = f"{ip:<20} # {country}"
        output_lines.append(formatted_line)

    fn = "data/input/ip/pia.txt"
    with open(fn, "w", encoding="utf-8") as file:
        file.write("\n".join(output_lines))

    print(f"Output saved to {fn}")


if __name__ == "__main__":
    fetch_pia_servers()
