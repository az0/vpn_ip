#!/usr/bin/env python3

import collections
import concurrent.futures
import ipaddress
import os
import socket


hostname_dir = 'data/input/hostname_ip'
ip_dir = 'data/input/ip'
final_fn = 'data/output/ip.txt'  # final, one line per IP, no duplicate IPs
allowlist_ip_fn= 'data/input/allowlist_ip.txt'
allowlist_hostname_fn ='data/input/allowlist_hostname.txt'
max_workers = 8


def clean_line(line: str) -> str:
    """Remove comments and whitespace from line"""
    return line.split('#')[0].split(',')[0].strip()

def resolve_hostname(hostname : str) -> list:
    """Return a list of IPv4 IPs for the given hostname"""
    #print(f'INFO: resolving hostname {hostname}')
    try:
        ip_addresses = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    except socket.gaierror as e:
        print(f"ERROR: Error resolving {hostname}: {e}")
        return []
    return [ip[4][0] for ip in ip_addresses]
    
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

    def check_ip_in_ranges(self, ip : str) -> bool:
        """Check if IP is in allowlist"""
        for r in self.ip_allowlist:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
                return True
        return False


def read_hosts(directory):
    """Read domains, one host per line"""
    hosts = []
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            print(f'reading hosts from {filename}')
            filepath = os.path.join(directory, filename)
            with open(filepath, "r") as file:
                for line in file:
                    hostname = clean_line(line)
                    if not len(hostname) > 5:
                        continue
                    if '-tor.' in hostname:  # example: hostname=us-co-21-tor.protonvpn.net
                        print(f'WARNING: skipping tor: {hostname}')
                        continue
                    hosts.append(hostname)
    return set(hosts)


def read_ips(directory):
    """Read IPs, one IP per line"""
    ips = []
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            print(f'reading IPs from {filename}')
            filepath = os.path.join(directory, filename)
            with open(filepath, "r") as file:
                for line in file:
                    ip = clean_line(line)
                    if not line:
                        continue
                    if not len(ip) >= 7:
                        continue
                    ips.append(ip)
    return set(ips)


def resolve_hosts(hosts):
    ip_to_hostnames = collections.defaultdict(set)

    allowlist = Allowlist()

    def resolve_hostname_and_add(hostname):
        ip_addresses = resolve_hostname(hostname)
        for ip_addr in sorted(ip_addresses):
            if allowlist.check_ip_in_ranges(ip_addr):
                print(f'WARNING: in allowlist {ip_addr} = {hostname}')
                continue
            if not bogons.is_public_ip(ip_addr):
                print(f'WARNING: {ip_addr} = {hostname} is not public')
                continue
            ip_to_hostnames[ip_addr].add(hostname)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(resolve_hostname_and_add, sorted(hosts))

    return ip_to_hostnames


def write_ips(ip_to_hostnames, ip_only):

    ip_only_filtered = [ip for ip in ip_only if ip not in ip_to_hostnames]

    ip_to_hostnames.update({ip: None for ip in ip_only_filtered})

    sorted_ips = sorted(ip_to_hostnames.keys(),
                        key=lambda ip: int(ipaddress.ip_address(ip)))

    print(f'INFO: count of IPs: {len(sorted_ips)}')

    with open(final_fn, "w") as output_file:
        for ip in sorted_ips:
            if ip_to_hostnames[ip]:
                hostnames = ",".join(sorted(ip_to_hostnames[ip]))
                output_file.write(f"{ip} # {hostnames}\n")
            else:
                output_file.write(f'{ip}\n')


def go():
    hosts = read_hosts(hostname_dir)
    ips_only = read_ips(ip_dir)
    ip_to_hostnames = resolve_hosts(hosts)
    write_ips(ip_to_hostnames, ips_only)


go()
