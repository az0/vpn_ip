# Imports
import glob
import ipaddress
import os
import re
import socket
import sys
import unittest

# Constants
adguard_input_fn = 'data/input/adguard.txt'
allowlist_ip_fn = 'data/input/allowlist_ip.txt'
allowlist_hostname_fn = 'data/input/allowlist_hostname.txt'

# Classes


class AdguardPatternChecker:
    def __init__(self, patterns: list):
        """Initialize with precompiled regex patterns"""
        self.compiled_patterns = [re.compile(adguard_pattern.replace('||', r'(^|\.)').rstrip(
            '^') + '$', re.IGNORECASE) for adguard_pattern in patterns]

    def check_fqdn(self, fqdn: str) -> bool:
        """Check if FQDN matches any of the precompiled patterns"""
        return any(pattern.search(fqdn) for pattern in self.compiled_patterns)


class Allowlist:
    def __init__(self):
        self.ip_allowlist = set()
        with open(allowlist_ip_fn, 'r', encoding='utf-8') as f:
            for line in f:
                line = clean_line(line)
                if not line:
                    continue
                self.ip_allowlist.add(line)
        self.hostname_allowlist = set()
        with open(allowlist_hostname_fn, 'r', encoding='utf-8') as f:
            for line in f:
                hostname = clean_line(line)
                if not hostname:
                    continue
                if not len(hostname) > 5:
                    continue
                hostnames = resolve_hostname(hostname)
                self.hostname_allowlist.update({hostname})
                for ip in hostnames:
                    self.ip_allowlist.add(ip)

    def check_hostname_in_allowlist(self, hostname: str) -> bool:
        assert isinstance(hostname, str)
        return hostname in self.hostname_allowlist

    def check_ip_in_ranges(self, ip: str) -> bool:
        """Check if IP is in allowlist"""
        assert isinstance(ip, str)
        for r in self.ip_allowlist:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
                return True
        return False


class TestCommon(unittest.TestCase):

    def test_allowlist(self):
        allowlist = Allowlist()
        self.assertEqual(allowlist.check_hostname_in_allowlist('shop.proton.me'), True)
        self.assertEqual(allowlist.check_hostname_in_allowlist('protonvpn.com'), False)
        self.assertEqual(allowlist.check_hostname_in_allowlist(''), False)
        self.assertEqual(allowlist.check_ip_in_ranges('1.1.1.1'), True)
        self.assertEqual(allowlist.check_ip_in_ranges('2.2.2.2'), False)
        self.assertEqual(allowlist.check_ip_in_ranges('127.0.0.1'), False)
        self.assertEqual(allowlist.check_ip_in_ranges('0.0.0.0'), False)

    def test_check_fqdn_against_adguard(self):
        test_cases = (
            ('blog.example.org', ['||example.org^'], True),
            ('example.org', ['||example.org^'], True),
            ('barexample.org', ['||example.org^'], False),
            ('example.com', ['||example.org^'], False),
            ('example.org.uk', ['||example.org^'], False),
        )
        for fqdn, patterns, expected in test_cases:
            with self.subTest(fqdn=fqdn, patterns=patterns, expected=expected):
                adguard_checker = AdguardPatternChecker(patterns)
                self.assertEqual(adguard_checker.check_fqdn(fqdn), expected)

    def test_sort_fqdns(self):
        fqdns = ['blog.example.com', 'mail.example.com', 'api.example.org', 'docs.example.org']
        self.assertEqual(sort_fqdns(fqdns), fqdns)
        self.assertEqual(sort_fqdns(fqdns[::-1]), fqdns)
        self.assertEqual(sort_fqdns([]), [])
        # using list comprehension to make new list, for each element in fqdns, prefix with '||' and suffix with '^'
        adguard_list = ['||' + fqdn + '^' for fqdn in fqdns]
        self.assertEqual(sort_fqdns(adguard_list), adguard_list)
        self.assertEqual(sort_fqdns(adguard_list[::-1]), adguard_list)

# Functions


def add_new_hostnames_to_file(dst_fn, get_subdomains_func, *args):
    """
    Add new hostnames to a file.

    The file must already exist.
    """
    full_fn = os.path.join('data/input/hostname_ip', dst_fn)
    known_hostnames = read_hostnames_from_file(full_fn)
    print(f'* count of known hostnames: {len(known_hostnames)}')

    api_hostnames = get_subdomains_func(*args)
    print(f'* count of API hostnames: {len(api_hostnames)}')

    new_hostnames = set(api_hostnames) - set(known_hostnames)

    if not new_hostnames:
        print('* no new hostnames found')
        return

    print(f'* writing  {len(new_hostnames)} new hostnames to {full_fn}')
    with open(full_fn, 'a', encoding="utf-8") as file:
        for hostname in sorted(new_hostnames):
            file.write(f'{hostname}\n')


def clean_line(line: str) -> str:
    """Remove comments and whitespace from line"""
    return line.strip('\n').split('#')[0].split(',')[0].strip()


def read_hostnames_from_file(filename: str) -> list:
    """Return every unique hostname from input file"""
    print(f'reading hosts from {filename}')
    hostnames = set()
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            hostname = clean_line(line)
            if '-tor.' in hostname:  # example: hostname=us-co-21-tor.protonvpn.net
                # print(f'WARNING: skipping tor: {hostname}')
                continue
            if hostname:
                hostnames.add(hostname)
    return list(hostnames)


def read_input_hostnames(input_hostname_pattern) -> list:
    """Return every unique hostname from input directory (multiple files)"""
    hostnames = set()
    for filename in glob.glob(input_hostname_pattern):
        hostnames.update(read_hostnames_from_file(filename))
    return list(hostnames)


def resolve_hostname(hostname: str) -> list:
    """Return a list of IPv4 IPs for the given hostname

    If there is an error resolving the hostname, return an empty list

    """
    # print(f'INFO: resolving hostname {hostname}')
    try:
        ip_addresses = socket.getaddrinfo(
            hostname, None, family=socket.AF_INET)
    except socket.gaierror as e:
        # print(f"ERROR: Error resolving {hostname}: {e}")
        return []
    ret = {ip[4][0] for ip in ip_addresses}
    return list(ret)


def sort_fqdns(fqdns: list) -> list:
    """Sort fully qualified domain names with reversed parts

    Example result:
    blog.example.com
    mail.example.com    
    api.example.org
    docs.example.org

    Sorting reduces the size of the diff.
    """
    return sorted(fqdns, key=lambda fqdn: fqdn.lower().split('.')[::-1])


def write_hostnames_to_text_file(filename, hostnames):
    assert isinstance(filename, str)
    assert isinstance(hostnames, list)
    print(f'writing {len(hostnames):,} hostnames to {filename}')
    script_filename = os.path.basename(sys.argv[0])
    with open(filename, "w", encoding="utf-8") as file:
        file.write(f'# This file was automatically generated by {script_filename}\n')
        file.write('\n'.join(hostnames))
        file.write('\n')

# Main Execution Logic (if any)
# Add any script logic here if needed
