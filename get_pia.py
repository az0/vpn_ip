#!/usr/bin/env python3
"""
Originally by DEVisions
https://github.com/az0/vpn_ip/issues/4
"""
import requests
import csv


def fetch_pia_servers():
    url = "https://raw.githubusercontent.com/Lars-/PIA-servers/refs/heads/master/export.csv"
    response = requests.get(url)

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
        ip, country, timestamp = row[0], row[1], row[2]
        formatted_line = f"{ip:<20} # piavpn, {country}, {timestamp}"
        output_lines.append(formatted_line)

    fn = "data/input/ip/pia.txt"
    with open(fn, "w") as file:
        file.write("\n".join(output_lines))

    print(f"Output saved to {fn}")


if __name__ == "__main__":
    fetch_pia_servers()
