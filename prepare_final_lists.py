#!/usr/bin/env python3
"""
This reads all the input hostname and IP addresses.
It combines duplicates and filters out hostnames that are invalid.
Finally, it writes one list of hostnames and one list of IP addresses.
"""

# built-in
import argparse
import collections
import concurrent.futures
import datetime
import lzma
import ipaddress
import json
import unittest
import os
import sys

# third-party import
import bogons
import requests
import tldextract
import tqdm

# local import
from common import (AdguardPatternChecker, Allowlist,
                    clean_line, read_input_hostnames,
                    resolve_hostname, sort_fqdns)

IP_DIR = 'data/input/ip'
FINAL_IP_FN = 'data/output/ip.txt'  # final, one line per IP, no duplicate IPs
FINAL_HOSTNAME_FN = 'data/output/hostname.txt'
INPUT_HOSTNAME_ONLY_PATTERN = 'data/input/hostname_only/*.txt'
INPUT_HOSTNAME_IP_PATTERN = 'data/input/hostname_ip/*.txt'
ADGUARD_OUTPUT_FN = 'data/output/adguard.txt'
MAX_WORKERS = 8
R2_CACHE_URL = 'https://az0-vpnip-public.oooninja.com/ip_cache.json.lzma'
LOCAL_CACHE_PATH = 'data/cache/ip_cache.json.lzma'
ALIAS_MAP = {
    "holax.io": "hola",
    "holavpn.net": "hola",
    "hola.org": "hola",
    "nordvpn.com": "nordvpn",
    "nordvpn": "nordvpn",
    "windscribe.com": "windscribe",
    "windscribe": "windscribe",
    "deepstateplatypus.com": "windscribe",
    "totallyacdn.com": "windscribe",
    "whiskergalaxy.com": "windscribe",
    "block-only-if-you-have-a-small-pee-pee.io": "windscribe",
    "staticnetcontent.com": "windscribe",
    "prmsrvs.com": "browsec",
    "frmdom.com": "browsec",
    "trafcfy.com": "browsec",
    "hoxx.com": "hoxx",
    "spoken.fun": "hoxx",
    "surprise.pics": "hoxx",
    "chester.run": "hoxx",
    "mixing.run": "hoxx",
    "pursuant.run": "hoxx",
    "sciences.run": "hoxx",
    "gen4.ninja": "cyberghost",
}


class TestPrepareFinalLists(unittest.TestCase):
    """Test prepare_final_lists module"""

    def test_fqdns_not_matching_pattern(self):
        """Test fqdns_not_matching_pattern()"""
        patterns = [
            '||example1.com^',
            'ample2.org|',
            '|example3'
        ]
        pattern_checker = AdguardPatternChecker(patterns)
        fqdns_match = [
            # Matches ||example1.com^
            'sub.example1.com',
            'example1.com',
            # Matches ample2.org|
            'example2.org',
            # Matches |example3
            'example3.org',
        ]
        fqdns_not_match = [
            # No match
            'noexample1.com',
            'example2.org.com',
            'test.example3',
            'foo.com',
            'a.b.test.net'
        ]
        actual_output = fqdns_not_matching_pattern(fqdns_match + fqdns_not_match, pattern_checker)
        self.assertCountEqual(actual_output, fqdns_not_match)

    def test_fqdns_not_matching_pattern_empty_input(self):
        patterns = ['||example.com^']
        pattern_checker = AdguardPatternChecker(patterns)
        fqdns = []
        expected_output = []
        actual_output = fqdns_not_matching_pattern(fqdns, pattern_checker)
        self.assertEqual(actual_output, expected_output)

    def test_fqdns_not_matching_pattern_empty_patterns(self):
        patterns = []
        pattern_checker = AdguardPatternChecker(patterns)
        fqdns = ['a.com', 'b.net', 'c.org']
        actual_output = fqdns_not_matching_pattern(fqdns, pattern_checker)
        self.assertEqual(actual_output, fqdns)

    def test_resolve_hosts(self):
        """Test resolve_hosts()"""
        input_fqdns = ['example.com', 'example.org', 'doesnotexist.example.com', 'private.host', 'local.host', 'cloudflare.host']
        resolver_cache = collections.defaultdict(set)
        resolver_cache['example.com'] = ['1.2.3.4']
        resolver_cache['example.org'] = ['5.6.7.8']
        resolver_cache['doesnotexist.example.com'] = []
        resolver_cache['private.host'] = ['0.0.0.0']
        resolver_cache['local.host'] = ['127.0.0.1']
        resolver_cache['cloudflare.host'] = ['104.26.8.89']
        (ret_hosts, ret_ip_to_root_domains) = resolve_hosts(input_fqdns, min_resolved_host_count=2, resolver_cache=resolver_cache, update_cache=False)
        self.assertEqual(ret_hosts, set(['example.com', 'example.org', 'cloudflare.host']))
        self.assertEqual(ret_ip_to_root_domains, {'1.2.3.4': {'example.com'}, '5.6.7.8': {'example.org'}})


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
    ext = tldextract.extract(fqdn)
    return '.'.join([ext.domain, ext.suffix])


def resolve_hosts(input_fqdns: list, min_resolved_host_count, resolver_cache=None, update_cache=False) -> dict:
    """Resolve FQDNs to IPs addresses

    Args:
        hosts: list of hostnames

    Returns:
        tuple (valid_hostnames, ip_addresses)
        valid_hostnames is a set of valid hostnames
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
        # Use cache if available
        if resolver_cache is not None and this_fqdn in resolver_cache:
            ip_addresses = resolver_cache[this_fqdn]
        else:
            ip_addresses = resolve_hostname(this_fqdn)
            if update_cache and resolver_cache is not None:
                resolver_cache[this_fqdn] = ip_addresses
        root_domain = get_root_domain(this_fqdn)
        for this_ip_addr in sorted(ip_addresses):
            if allowlist.check_ip_in_ranges(this_ip_addr):
                hostnames_with_ip_in_allowlist.append(this_fqdn)
                valid_fqdns.add(this_fqdn)
                continue
            if not bogons.is_public_ip(this_ip_addr):
                hostnames_with_non_public_ip.append(this_fqdn)
                continue
            valid_fqdns.add(this_fqdn)
            ip_to_root_domains[this_ip_addr].add(root_domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        list(tqdm.tqdm(executor.map(resolve_hostname_and_add, sorted(input_fqdns)), total=len(input_fqdns)))

    print('resolve_hosts() stats')
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


def fqdns_not_matching_pattern(fqdns, pattern_checker):
    """Return list of FQDNs that do not match any pattern

    Args:
        fqdns: list of FQDNs
        pattern_checker: AdguardPatternChecker instance

    Returns:
        list of FQDNs that do not match any pattern
    """
    ret = []
    for fqdn in sort_fqdns([fqdn for fqdn in fqdns if not pattern_checker.check_fqdn(fqdn)]):
        ret.append(fqdn)
    return ret


def write_hostnames(fqdns: list, pattern_list: list) -> None:
    """Write final output list of FQDNs

    fqdns: list of FQDNs
    pattern_list: list of Adguard patterns
    """
    assert isinstance(fqdns, (list, set))
    assert isinstance(pattern_list, list)
    assert len(fqdns) > 0
    assert len(pattern_list) > 0
    pattern_checker = AdguardPatternChecker(pattern_list)
    with open(ADGUARD_OUTPUT_FN, "w", encoding="utf-8") as output_file:
        output_file.write(f"# {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        output_file.write('# This is a blocklist of VPNs in Adguard format.\n')
        output_file.write("# begin patterns\n")
        for pattern in sort_fqdns(pattern_list):
            output_file.write(f"{pattern}\n")
        output_file.write("# end patterns\n")
        # Write FQDNs that don't match any patterns in Adguard format.
        output_file.write('\n'.join(fqdns_not_matching_pattern(fqdns, pattern_checker)) + '\n')
    with open(FINAL_HOSTNAME_FN, "w", encoding="utf-8") as output_file:
        output_file.write(f"# {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        for fqdn in sort_fqdns(fqdns):
            output_file.write(f"{fqdn}\n")


def canonicalize_hostnames(hostnames):
    """Simplify list of hostnames using ALIAS_MAP"""
    canonical = set()
    for h in hostnames:
        canonical.add(ALIAS_MAP.get(h, h))
    return sorted(canonical)


def write_ips(ip_to_root_domains: dict, ips_only: dict) -> None:
    """Write final list of IP addresses to file

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

    with open(FINAL_IP_FN, "w", encoding="utf-8") as output_file:
        output_file.write(f"# {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        for ip in sorted_ips:
            hostnames_list = canonicalize_hostnames(set(merged_dict[ip]))
            hostnames_str = ",".join(hostnames_list)
            output_file.write(f"{ip} # {hostnames_str}\n")


def download_and_load_resolver_cache(cache_url, cache_path):
    """Download and load resolver cache from R2"""
    print(f"Downloading resolver cache from {cache_url}")
    r = requests.get(cache_url, timeout=60)
    r.raise_for_status()
    with open(cache_path, 'wb') as f:
        f.write(r.content)
    with lzma.open(cache_path, 'rt', encoding='utf-8') as f:
        cache_data = json.load(f)
    print(f"Loaded resolver cache with {len(cache_data['host_to_ips'])} entries, created {cache_data['created_utc']}")
    return cache_data['host_to_ips']


def write_resolver_cache(cache_path, host_to_ips):
    """Write resolver cache to file"""
    data = {
        'created_utc': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'host_to_ips': host_to_ips
    }
    with lzma.open(cache_path, 'wt', encoding='utf-8') as f:
        json.dump(data, f)
    print(f"Wrote resolver cache with {len(host_to_ips)} entries to {cache_path}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Prepare final VPN/IP lists")
    parser.add_argument('--use-resolver-cache', action='store_true',
                        help='Use public R2 resolver cache for hostname resolution')
    args = parser.parse_args()

    os.makedirs(os.path.dirname(LOCAL_CACHE_PATH), exist_ok=True)

    resolver_cache = None
    if args.use_resolver_cache:
        resolver_cache = download_and_load_resolver_cache(R2_CACHE_URL, LOCAL_CACHE_PATH)
        update_cache = False
    else:
        resolver_cache = {}
        update_cache = True

    hostnames_only, patterns_only = read_input_hostnames(INPUT_HOSTNAME_ONLY_PATTERN)
    hostnames_ip, patterns_ip = read_input_hostnames(INPUT_HOSTNAME_IP_PATTERN)
    all_patterns = list(set(patterns_only) | set(patterns_ip))
    pattern_to_hostname_only = []
    for pattern in sort_fqdns(all_patterns):
        if pattern.startswith('||') and pattern.endswith('^'):
            # Convert pattern ||example.com^ to hostname example.com
            pattern_hostname = pattern[2:-1]
            if not pattern_hostname in hostnames_only:
                pattern_to_hostname_only.append(pattern_hostname)
    fqdns_to_resolve_no_ip_collection = list(set(hostnames_only) | set(pattern_to_hostname_only))
    (valid_fqdns1, _ip_to_root_domains_discard) = resolve_hosts(
        fqdns_to_resolve_no_ip_collection, 50, resolver_cache=resolver_cache, update_cache=update_cache)
    (valid_fqdns2, ip_to_root_domains) = resolve_hosts(hostnames_ip,
                                                       20, resolver_cache=resolver_cache, update_cache=update_cache)
    valid_fqdns = list(valid_fqdns1 | valid_fqdns2)

    write_hostnames(valid_fqdns, all_patterns)
    ips_only = read_ips(IP_DIR)
    write_ips(ip_to_root_domains, ips_only)

    if update_cache:
        write_resolver_cache(LOCAL_CACHE_PATH, resolver_cache)

    print(f"{sys.argv[0]} is done")


if __name__ == "__main__":
    main()
