#!/usr/bin/env python3
"""
This reads all the input hostname and IP addresses.
It combines duplicates and filters out hostnames that are invalid.
Finally, it writes one list of hostnames and one list of IP addresses.
"""

import collections
import concurrent.futures
import ipaddress
import os

import bogons
import tqdm

from common import clean_line, read_input_hostnames, resolve_hostname


ip_dir = 'data/input/ip'
final_ip_fn = 'data/output/ip.txt'  # final, one line per IP, no duplicate IPs
final_hostname_fn = 'data/output/hostnames.txt'
allowlist_ip_fn = 'data/input/allowlist_ip.txt'
allowlist_hostname_fn = 'data/input/allowlist_hostname.txt'
max_workers = 8
min_resolved_host_count = 100


class Allowlist:
    def __init__(self):
        self.ip_allowlist = set()
        with open(allowlist_ip_fn, 'r') as f:
            for line in f:
                line = clean_line(line)
                if not line:
                    continue
                self.ip_allowlist.add(line)
        with open(allowlist_hostname_fn, 'r') as f:
            for line in f:
                hostname = clean_line(line)
                if not hostname:
                    continue
                if not len(hostname) > 5:
                    continue
                hostnames = resolve_hostname(hostname)
                for ip in hostnames:
                    self.ip_allowlist.add(ip)

    def check_ip_in_ranges(self, ip: str) -> bool:
        """Check if IP is in allowlist"""
        for r in self.ip_allowlist:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
                return True
        return False


def read_ips(directory):
    """Read IPs, one IP per line"""
    ips = []
    min_ip_length = len('0.0.0.0')
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            print(f'reading IPs from {filename}')
            filepath = os.path.join(directory, filename)
            with open(filepath, "r") as file:
                for line in file:
                    ip = clean_line(line)
                    if not line:
                        continue
                    if not len(ip) >= min_ip_length:
                        continue
                    ips.append(ip)
    return set(ips)


def resolve_hosts(hosts: list) -> dict:
    assert len(hosts) > 0
    ip_to_hostnames = collections.defaultdict(set)

    allowlist = Allowlist()
    hostnames_with_non_public_ip = []
    hostnames_with_ip_in_allowlist = []

    def resolve_hostname_and_add(hostname):
        nonlocal hostnames_with_non_public_ip, hostnames_with_ip_in_allowlist
        ip_addresses = resolve_hostname(hostname)
        for ip_addr in sorted(ip_addresses):
            if allowlist.check_ip_in_ranges(ip_addr):
                hostnames_with_ip_in_allowlist.append(hostname)
            if not bogons.is_public_ip(ip_addr):
                hostnames_with_non_public_ip.append(hostname)
            else:
                ip_to_hostnames[ip_addr].add(hostname)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(tqdm.tqdm(executor.map(resolve_hostname_and_add, sorted(hosts)), total=len(hosts)))

    

    print(f'resolve_hosts() stats')
    print(f'* count of unique IPs: {len(ip_to_hostnames):,}')
    unique_host_count = len(hosts)
    print(f'* count of hosts: {unique_host_count:,}')
    resolvable_host_names = set(
        [hostname for hostnames in ip_to_hostnames.values() for hostname in hostnames])
    resolved_host_count = len(resolvable_host_names)
    print(f'* count of unique hostnames: {resolved_host_count:,}')
    print(f'* count of unresolvable hosts: {len(hosts) - resolved_host_count:,}')
    print(f'* count of hostnames with IP in allowlist: {len(hostnames_with_ip_in_allowlist):,}')
    print(f'* count of hostnames with non-public IP: {len(set(hostnames_with_non_public_ip):,)}')
    assert unique_host_count >= 0
    assert resolved_host_count >= 0
    assert resolved_host_count <= unique_host_count
    assert resolved_host_count >= min_resolved_host_count
    return ip_to_hostnames


def sort_hostnames(hostnames: list) -> list:
    """Sort hostnames with reversed parts

    Example result
    blog.example.com
    mail.example.com    
    api.example.org
    docs.example.org
    """
    return sorted(hostnames, key=lambda hostname: hostname.lower().split('.')[::-1])


def write_hostnames(ip_to_hostnames):
    # get all hostnames that have at least one valid IP.
    hostnames_with_valid_ip = set()
    for hostnames in ip_to_hostnames.values():
        hostnames_with_valid_ip.update(hostnames)

    # Write final hostnames to file.
    with open(final_hostname_fn, "w", encoding="utf-8") as output_file:
        for hostname in sort_hostnames(hostnames_with_valid_ip):
            output_file.write(f"{hostname}\n")


def write_ips(ip_to_hostnames, ip_only):

    ip_only_filtered = [ip for ip in ip_only if ip not in ip_to_hostnames]

    ip_to_hostnames.update({ip: None for ip in ip_only_filtered})

    sorted_ips = sorted(ip_to_hostnames.keys(),
                        key=lambda ip: int(ipaddress.ip_address(ip)))

    print(f'count of final IPs to write: {len(sorted_ips)}')

    with open(final_ip_fn, "w") as output_file:
        for ip in sorted_ips:
            if ip_to_hostnames[ip]:
                hostnames = ",".join(sort_hostnames(ip_to_hostnames[ip]))
                output_file.write(f"{ip} # {hostnames}\n")
            else:
                output_file.write(f'{ip}\n')


def go():
    hosts = read_input_hostnames()
    ip_to_hostnames = resolve_hosts(hosts)
    write_hostnames(ip_to_hostnames)
    ips_only = read_ips(ip_dir)
    write_ips(ip_to_hostnames, ips_only)


go()
