#!/usr/bin/env python3
"""
This reads all the input hostname and IP addresses.
It combines duplicates and filters out hostnames that are invalid.
Finally, it writes one list of hostnames and one list of IP addresses.
"""

# built-in
import collections
import concurrent.futures
import ipaddress
import os
import re
import sys
import unittest

# local import
from common import clean_line, read_hostnames_from_file, read_input_hostnames, resolve_hostname

# third-party import
import bogons
import tqdm


ip_dir = 'data/input/ip'
final_ip_fn = 'data/output/ip.txt'  # final, one line per IP, no duplicate IPs
final_hostname_fn = 'data/output/hostname.txt'
input_hostname_only_pattern = 'data/input/hostname_only/*.txt'
input_hostname_ip_pattern = 'data/input/hostname_ip/*.txt'
allowlist_ip_fn = 'data/input/allowlist_ip.txt'
allowlist_hostname_fn = 'data/input/allowlist_hostname.txt'
adguard_input_fn = 'data/input/adguard.txt'
adguard_output_fn = 'data/output/adguard.txt'
max_workers = 8
min_resolved_host_count = 50


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
    """Read IPs, one IP per line

    Returns a dictionary with IP as key and list of sources as value

    """
    ips = collections.defaultdict(set)
    allowlist = Allowlist()
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            print(f'reading IPs from {filename}')
            source_tag = filename.replace('.txt', '').replace('_api', '')
            filepath = os.path.join(directory, filename)
            with open(filepath, "r", encoding="utf-8") as file:
                for line in file:
                    ip = clean_line(line)
                    if not ip:
                        continue
                    if allowlist.check_ip_in_ranges(ip):
                        continue
                    if not bogons.is_public_ip(ip):
                        continue
                    ips[ip].add(source_tag)
    return ips


def get_root_domain(fqdn: str) -> str:
    """Get root domain from FQDN"""
    import tldextract
    ext = tldextract.extract(fqdn)
    return '.'.join([ext.domain, ext.suffix])


def resolve_hosts(input_fqdns: list) -> dict:
    """Resolve FQDNs to IPs addresses

    Args:
        hosts: list of hostnames

    Returns:
        tuple (valid_hostnames, ip_addresses)
        ip_addresses is a dict with IP as key and list of root domains as values


    """
    assert len(input_fqdns) > 0
    ip_to_root_domains = collections.defaultdict(set)

    allowlist = Allowlist()

    valid_fqdns = set()
    hostnames_with_non_public_ip = []
    hostnames_with_ip_in_allowlist = []

    def resolve_hostname_and_add(this_fqdn):
        nonlocal hostnames_with_non_public_ip, hostnames_with_ip_in_allowlist, valid_fqdns
        ip_addresses = resolve_hostname(this_fqdn)
        root_domain = get_root_domain(this_fqdn)
        for this_ip_addr in sorted(ip_addresses):
            if allowlist.check_ip_in_ranges(this_ip_addr):
                hostnames_with_ip_in_allowlist.append(this_fqdn)
                continue
            if not bogons.is_public_ip(this_ip_addr):
                hostnames_with_non_public_ip.append(this_fqdn)
                continue
            valid_fqdns.add(this_fqdn)
            ip_to_root_domains[this_ip_addr].add(root_domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(tqdm.tqdm(executor.map(resolve_hostname_and_add, sorted(input_fqdns)), total=len(input_fqdns)))

    print(f'resolve_hosts() stats')
    unique_host_count = len(input_fqdns)
    print(f'* count of input FQDNs: {unique_host_count:,}')
    print(f'* count of unique, valid IPs resolved: {len(ip_to_root_domains):,}')
    resolvable_host_names = set([hostname for hostnames in ip_to_root_domains.values() for hostname in hostnames])
    resolved_host_count = len(resolvable_host_names)
    print(f'* count of unique hostnames: {resolved_host_count:,}')
    print(f'* count of unresolvable hosts: {len(input_fqdns) - resolved_host_count:,}')
    print(f'* count of hostnames with IP in allowlist: {len(hostnames_with_ip_in_allowlist):,}')
    print(f'* count of hostnames with non-public IP: {len(set(hostnames_with_non_public_ip)):,}')
    assert unique_host_count >= 0
    assert resolved_host_count >= 0
    assert resolved_host_count <= unique_host_count
    assert resolved_host_count >= min_resolved_host_count, f'{resolved_host_count} vs {min_resolved_host_count}'

    return (valid_fqdns, ip_to_root_domains)


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


def check_fqdn_against_adguard(fqdn: str, patterns: list) -> bool:
    """Check if FQDN matches a list of Adguard-style patterns

    This supports a minimal subset of Adguard syntax.

    Example pattern '||example.org^
    Matches: foo.example.org, example.org
    Does not match: barexample.org, example.com, example.org.uk
    """

    for adguard_pattern in patterns:
        # Translate Adguard to regex.
        re_pattern = adguard_pattern.replace('||', r'(^|\.)').rstrip('^')
        re_pattern += '$'
        if re.search(re_pattern, fqdn, re.IGNORECASE):
            return True
    return False


def write_hostnames(fqdns: list, adguard_input_list: list) -> None:
    """Write final output list of FQDNs."""
    assert isinstance(fqdns, (list, set))
    assert isinstance(adguard_input_list, list)
    assert len(fqdns) > 0
    assert len(adguard_input_list) > 0
    with open(adguard_output_fn, "w", encoding="utf-8") as output_file:
        output_file.write('# This is a blocklist of VPNs in Adguard format.\n')
        output_file.write(f"# begin {adguard_input_fn}\n")
        for pattern in sort_fqdns(adguard_input_list):
            output_file.write(f"{pattern}\n")
        output_file.write(f"# end {adguard_input_fn}\n")
        for fqdn in sort_fqdns([fqdn for fqdn in fqdns if not check_fqdn_against_adguard(fqdn, adguard_input_list)]):
            output_file.write(f"||{fqdn}^\n")
    with open(final_hostname_fn, "w", encoding="utf-8") as output_file:
        for fqdn in sort_fqdns(fqdns):
            output_file.write(f"{fqdn}\n")


def write_ips(ip_to_root_domains: dict, ips_only: dict) -> None:
    """"Write final list of IP addresses to file

    Args:
        ip_to_root_domains: dict with IP as key and list of root domains as values
        ips_only: dict with IP as key and list of sources as values

    """
    assert isinstance(ip_to_root_domains, dict)
    assert isinstance(ips_only, dict)
    assert len(ip_to_root_domains) > 0
    assert len(ips_only) > 0
    assert isinstance(list(ips_only.values())[0], set)
    assert isinstance(list(ip_to_root_domains.values())[0], set)

    merged_dict = collections.defaultdict(set)
    for key in ip_to_root_domains.keys() | ips_only.keys():
        merged_dict[key] = ip_to_root_domains.get(key, set()) | ips_only.get(key, set())

    sorted_ips = sorted(merged_dict.keys(),
                        key=lambda ip: int(ipaddress.ip_address(ip)))

    print(f'count of final IPs to write: {len(sorted_ips):,}')

    with open(final_ip_fn, "w", encoding="utf-8") as output_file:
        for ip in sorted_ips:
            hostnames_list = sort_fqdns(set(merged_dict[ip]))
            hostnames_str = ",".join(hostnames_list)
            output_file.write(f"{ip} # {hostnames_str}\n")


def go():
    fqdns_hostnames_only = read_input_hostnames(input_hostname_only_pattern)
    fqdns_hostnames_ip = read_input_hostnames(input_hostname_ip_pattern)
    (valid_fqdns1, ip_to_root_domains_discard) = resolve_hosts(fqdns_hostnames_only)
    (valid_fqdns2, ip_to_root_domains) = resolve_hosts(fqdns_hostnames_ip)
    valid_fqdns = list(set(valid_fqdns1).union(set(valid_fqdns2)))
    adguard_patterns = read_hostnames_from_file(adguard_input_fn)
    write_hostnames(valid_fqdns, adguard_patterns)
    ips_only = read_ips(ip_dir)
    write_ips(ip_to_root_domains, ips_only)


class TestPrepareFinalLists(unittest.TestCase):
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
                self.assertEqual(check_fqdn_against_adguard(fqdn, patterns), expected)

    def test_sort_fqdns(self):
        fqdns = ['blog.example.com', 'mail.example.com', 'api.example.org', 'docs.example.org']
        self.assertEqual(sort_fqdns(fqdns), fqdns)
        self.assertEqual(sort_fqdns(fqdns[::-1]), fqdns)
        self.assertEqual(sort_fqdns([]), [])
        # using list comprehension to make new list, for each element in fqdns, prefix with '||' and suffix with '^'
        adguard_list = ['||' + fqdn + '^' for fqdn in fqdns]
        self.assertEqual(sort_fqdns(adguard_list), adguard_list)
        self.assertEqual(sort_fqdns(adguard_list[::-1]), adguard_list)


if __name__ == "__main__":
    if '--test' in sys.argv:
        sys.argv.remove('--test')
        unittest.main()
    else:
        go()
