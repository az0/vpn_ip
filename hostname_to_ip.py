#!/usr/bin/env python3

import collections
import ipaddress
import os
import socket

hostname_dir = 'data/input/hostname_ip'
ip_dir = 'data/input/ip'
final_fn = 'data/output/ip.txt'  # final, one line per IP, no duplicate IPs

# https://www.cloudflare.com/en-gb/ips/
# https://en.wikipedia.org/wiki/1.1.1.1
# https://bgp.he.net/AS13335#_prefixes
# https://en.wikipedia.org/wiki/Google_Public_DNS
# https://bgp.he.net/AS15169#_prefixes


def check_ip_in_ranges(ip):
    ranges = (
        "1.0.0.0/24",
        "1.1.1.0/24",
        "8.8.4.0/24",
        "8.8.8.0/24",
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22"
    )
    for r in ranges:
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
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    hostname = line.split('#')[0]  # remove comment at end
                    hostname = line.split(',')[0]
                    if not len(hostname) > 5:
                        continue
                    if '-tor.' in hostname:  # example: hostname=us-co-21-tor.protonvpn.net
                        print(f'WARNING: skipping tor: {hostname}')
                        continue
                    hosts.append(hostname)
    return set(hosts)

def read_ips(directory):
    """Read IPs, one IP per line"""
    ips =  []
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            print(f'reading IPs from {filename}')
            filepath = os.path.join(directory, filename)
            with open(filepath, "r") as file:
                for line in file:
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    ip = line.split('#')[0]  # remove comment at end
                    if not len(ip) >= 7:
                        continue
                    ips.append(ip)
    return set(ips)

def resolve_hosts(hosts):
    ip_to_hostnames = collections.defaultdict(set)

    for hostname in sorted(hosts):
        print(f'INFO: hostname={hostname}')
        try:
            ip_addresses = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            print(f"ERROR: Error resolving {hostname}: {e}")
            continue
        # Loop over each IP address and add it to the ip_to_hostnames dictionary
        for ip_address in sorted(ip_addresses):
            ip_addr = ip_address[4][0]
            if check_ip_in_ranges(ip_addr):
                print(f'WARNING: in whitelist {ip_addr} = {hostname}')
                continue
            ip_to_hostnames[ip_addr].add(hostname)

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
