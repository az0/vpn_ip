#!/usr/bin/env python3
"""
This script combines all input hostnames into one list,
while filtering out duplicates and those that cannot be
resolved.
"""

# built-in

from concurrent.futures import ThreadPoolExecutor

# local
from common import clean_line, read_input_hostnames, resolve_hostname

# third-party
from tqdm import tqdm

# constants
OUTPUT_FN = 'data/output/hostnames.txt'


def resolve_hosts(hostnames: list) -> list:
    """Return a list of resolvable hostnames"""
    resolved_hosts = []
    unresolved_hosts = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        from concurrent.futures import as_completed
        futures = {executor.submit(
            resolve_hostname, hostname): hostname for hostname in hostnames}

        with tqdm(total=len(hostnames), desc='Resolving hostnames') as pbar:
            for future in as_completed(futures):
                hostname = futures[future]
                ip_addresses = future.result()
                if not ip_addresses:
                    unresolved_hosts.append(hostname)
                else:
                    resolved_hosts.append(hostname)
                # Manually update progress bar after each future completes
                pbar.update(1)

    print(f'original count: {len(hostnames):,}')
    print(f'unresolved count: {len(unresolved_hosts):,}')
    print(f'resolved count: {len(resolved_hosts):,}')
    return resolved_hosts


def sort_hostnames(hostnames: list) -> list:
    """Sort hostnames with reversed parts
    
    Example result
    blog.example.com
    mail.example.com    
    api.example.org
    docs.example.org
    """
    return sorted(hostnames, key=lambda hostname: hostname.lower().split('.')[::-1])

def main():
    hostnames = read_input_hostnames()
    resolved_hosts = resolve_hosts(hostnames)
    with open(OUTPUT_FN, 'w', encoding='utf-8') as output_file:
        output_file.write('\n'.join(sort_hostnames(resolved_hosts)))


if __name__ == '__main__':
    main()
