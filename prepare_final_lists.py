#!/usr/bin/env python3
"""
This reads all the input hostname and IP addresses.
It combines duplicates and filters out hostnames that are invalid.
Finally, it writes one list of hostnames and one list of IP addresses.

# Terminology
* hostname/FQDN: a fully qualified domain name (e.g., 'www.example.com')
* root domain: the registrable domain portion of an FQDN (e.g., 'example.com' from 'www.example.com')
* TLD: top-level domain (e.g., 'com' from 'example.com')
* bogon: an IP address that is not a valid, public IP address (e.g., '127.0.0.1')
"""

# built-in
import argparse
import collections
import datetime
import ipaddress
import json
import logging
import lzma
import os
import random
import sys
import tempfile
import unittest

# third-party import
import bogons
import requests
import tldextract

# local import
from common import (AdguardPatternChecker, Allowlist,
                    clean_line, read_input_hostnames,
                    sort_fqdns, setup_logging,
                    write_addresses_to_file, TEST_HOSTNAMES_VALID)
from resolver import resolve_hostnames_sync

IP_DIR = 'data/input/ip'
FINAL_IP_FN = 'data/output/ip.txt'  # final, one line per IP, no duplicate IPs
FINAL_HOSTNAME_FN = 'data/output/hostname.txt'
INPUT_HOSTNAME_ONLY_PATTERN = 'data/input/hostname_only/*.txt'
INPUT_HOSTNAME_IP_PATTERN = 'data/input/hostname_ip/*.txt'
ADGUARD_OUTPUT_FN = 'data/output/adguard.txt'
INDIVIDUAL_TIMEOUT_SECONDS = 60
DEFAULT_MAX_CONCURRENCY = 500
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
        """Test fqdns_not_matching_pattern() in normal usage"""
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
        """Test fqdns_not_matching_pattern() with empty input"""
        patterns = ['||example.com^']
        pattern_checker = AdguardPatternChecker(patterns)
        fqdns = []
        expected_output = []
        actual_output = fqdns_not_matching_pattern(fqdns, pattern_checker)
        self.assertEqual(actual_output, expected_output)

    def test_fqdns_not_matching_pattern_empty_patterns(self):
        """Test fqdns_not_matching_pattern() with empty patterns"""
        patterns = []
        pattern_checker = AdguardPatternChecker(patterns)
        fqdns = ['a.com', 'b.net', 'c.org']
        actual_output = fqdns_not_matching_pattern(fqdns, pattern_checker)
        self.assertEqual(actual_output, fqdns)

    def test_resolve_hosts_cache(self):
        """Test resolve_hosts() using cache"""
        input_fqdns = ['example.com', 'example.org', 'doesnotexist.example.com',
                       'private.host', 'local.host', 'cloudflare.host']
        resolver_cache = {
            'example.com': {'ips': ['1.2.3.4'], 'error': None},
            'example.org': {'ips': ['5.6.7.8'], 'error': None},
            'doesnotexist.example.com': {'ips': [], 'error': 'NXDOMAIN'},
            'private.host': {'ips': ['0.0.0.0'], 'error': None},
            'local.host': {'ips': ['127.0.0.1'], 'error': None},
            'cloudflare.host': {'ips': ['104.26.8.89'], 'error': None}
        }
        (ret_hosts, ret_ip_to_root_domains) = resolve_hosts(input_fqdns,
                                                            min_resolved_host_count=2, resolver_cache=resolver_cache, update_cache=False)
        self.assertEqual(ret_hosts, set(['example.com', 'example.org', 'cloudflare.host']))
        self.assertEqual(ret_ip_to_root_domains, {'1.2.3.4': {'example.com'}, '5.6.7.8': {'example.org'}})

    def test_resolve_hosts_real(self):
        """Test resolve_hosts() with real hostnames"""
        (ret_hosts, ret_ip_to_root_domains) = resolve_hosts(TEST_HOSTNAMES_VALID,
                                                            min_resolved_host_count=2, resolver_cache=None, update_cache=False)
        self.assertEqual(len(ret_hosts), len(TEST_HOSTNAMES_VALID))
        hostnames_with_ips = set([hostname for hostnames in ret_ip_to_root_domains.values() for hostname in hostnames])
        self.assertEqual(hostnames_with_ips, set(TEST_HOSTNAMES_VALID))

    def test_resolve_and_filter_hostnames_cached(self):
        """Test resolve_and_filter_hostnames() with cached data"""
        hostname_only = ['only1.example.com', 'only2.example.org']
        hostname_ip = ['both1.example.net', 'sub.both2.example.io']

        resolver_cache = {
            'only1.example.com': {'ips': ['1.1.1.1'], 'error': None},
            'only2.example.org': {'ips': ['2.2.2.2'], 'error': None},
            'both1.example.net': {'ips': ['3.3.3.3'], 'error': None},
            'sub.both2.example.io': {'ips': ['4.4.4.4'], 'error': None},
        }

        (valid_fqdns, ip_to_root_domains) = resolve_and_filter_hostnames(
            hostname_only, hostname_ip, resolver_cache=resolver_cache, update_cache=False
        )

        # All FQDNs should be in valid_fqdns
        expected_fqdns = set(hostname_only + hostname_ip)
        self.assertEqual(valid_fqdns, expected_fqdns)

        # Only IPs from hostname_ip should be in ip_to_root_domains
        # both1.example.net -> example.net, sub.both2.example.io -> example.io
        expected_ips = {'3.3.3.3', '4.4.4.4'}
        self.assertEqual(set(ip_to_root_domains.keys()), expected_ips)

        # Check root domains
        self.assertEqual(ip_to_root_domains['3.3.3.3'], {'example.net'})
        self.assertEqual(ip_to_root_domains['4.4.4.4'], {'example.io'})

    def test_resolve_and_filter_hostnames_shared_domain(self):
        """Test filtering when hostname_only and hostname_ip share root domains"""
        # Both lists have different subdomains of same root domain
        hostname_only = ['www.example.com', 'mail.example.org']
        hostname_ip = ['vpn.example.com', 'server.example.net']

        resolver_cache = {
            'www.example.com': {'ips': ['1.1.1.1'], 'error': None},
            'mail.example.org': {'ips': ['2.2.2.2'], 'error': None},
            'vpn.example.com': {'ips': ['3.3.3.3'], 'error': None},
            'server.example.net': {'ips': ['4.4.4.4'], 'error': None},
        }

        (valid_fqdns, ip_to_root_domains) = resolve_and_filter_hostnames(
            hostname_only, hostname_ip, resolver_cache=resolver_cache, update_cache=False
        )

        # All should be valid
        self.assertEqual(len(valid_fqdns), 4)

        # Only IPs from vpn.example.com and server.example.net should be included
        # Since they share root domain example.com with www.example.com,
        # the IP 3.3.3.3 should still be included because vpn.example.com is in hostname_ip
        expected_ips = {'3.3.3.3', '4.4.4.4'}
        self.assertEqual(set(ip_to_root_domains.keys()), expected_ips)
        self.assertEqual(ip_to_root_domains['3.3.3.3'], {'example.com'})
        self.assertEqual(ip_to_root_domains['4.4.4.4'], {'example.net'})


    def test_write_ips(self):


        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file path in a subdirectory
            test_file = os.path.join(temp_dir, 'test_output', 'ips.txt')

            ip_to_root_domains = {
                '1.2.3.4': {'example.com'},
                '5.6.7.8': {'example.org'}
            }
            ips_only = {
                '1.2.3.4': {'source1', 'source2'},
                '5.6.7.8': {'source3'}
            }

            # Call write_ips with the test file path
            write_ips(ip_to_root_domains, ips_only, final_ip_fn=test_file)

            # Verify the file was created and has content
            self.assertTrue(os.path.exists(test_file))
            with open(test_file, 'r') as f:
                content = f.read()
                self.assertIn('1.2.3.4', content)
                self.assertIn('5.6.7.8', content)

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
    """Get root domain from FQDN

    Example:
    >>> get_root_domain('example.com')
    'example.com'
    >>> get_root_domain('www.example.com')
    'example.com'
    """
    ext = tldextract.extract(fqdn)
    return '.'.join([ext.domain, ext.suffix])


def resolve_hosts(input_fqdns: list, min_resolved_host_count, resolver_cache=None, update_cache=False, max_concurrency=DEFAULT_MAX_CONCURRENCY) -> dict:
    """Resolve FQDNs to IP addresses using new async resolver

    Args:
        input_fqdns: list of hostnames to resolve
        min_resolved_host_count: minimum number of hosts that must resolve
        resolver_cache: dict mapping hostname to result dict (new format)
        update_cache: whether to update the cache
        max_concurrency: maximum concurrent DNS queries

    Returns:
        tuple (valid_hostnames, ip_to_root_domains)
        valid_hostnames is a set of valid hostnames
        ip_to_root_domains is a dict with IP as key and set of root domains as values
    """
    assert len(input_fqdns) > 0
    ip_to_root_domains = collections.defaultdict(set)
    allowlist = Allowlist()

    valid_fqdns = set()
    hostnames_with_non_public_ip = []
    hostnames_with_ip_in_allowlist = []
    unresolvable_hosts = []

    # Get hostnames that need resolution
    hostnames_to_resolve = []
    cached_results = {}

    for fqdn in input_fqdns:
        if resolver_cache is not None and fqdn in resolver_cache:
            cached_results[fqdn] = resolver_cache[fqdn]
        else:
            hostnames_to_resolve.append(fqdn)

    # Resolve uncached hostnames
    resolved_results = {}
    if hostnames_to_resolve:
        print(f"Resolving {len(hostnames_to_resolve):,} hostnames (using cache for {len(cached_results):,})...")
        resolved_results = resolve_hostnames_sync(hostnames_to_resolve, max_concurrency=max_concurrency)

        # Update cache if requested
        if update_cache and resolver_cache is not None:
            resolver_cache.update(resolved_results)

    # Combine cached and resolved results
    all_results = {**cached_results, **resolved_results}

    # Process results
    for fqdn, result in all_results.items():
        root_domain = get_root_domain(fqdn)

        # Check for errors
        if result['error'] is not None:
            unresolvable_hosts.append(result['error'])
            logging.debug("%s -> %s", fqdn, result['error'])
            continue

        # Process IPs
        ip_addresses = result['ips']
        if not ip_addresses:
            unresolvable_hosts.append('no_ip')
            continue

        for ip_addr in sorted(ip_addresses):
            if allowlist.check_ip_in_ranges(ip_addr):
                logging.debug("%s IP %s is in allowlist", fqdn, ip_addr)
                hostnames_with_ip_in_allowlist.append(fqdn)
                valid_fqdns.add(fqdn)
                continue
            if not bogons.is_public_ip(ip_addr):
                logging.debug("%s IP %s is not a public IP", fqdn, ip_addr)
                hostnames_with_non_public_ip.append(fqdn)
                continue
            # logging.debug("%s -> %s (valid)", fqdn, ip_addr)
            valid_fqdns.add(fqdn)
            ip_to_root_domains[ip_addr].add(root_domain)

    # Log statistics
    logging.info('resolve_hosts() stats')
    unique_host_count = len(input_fqdns)
    logging.info('* count of input FQDNs: %s', f'{unique_host_count:,}')
    logging.info('* count of unique, valid IPs resolved: %s', f'{len(ip_to_root_domains):,}')
    resolvable_host_names = set([hostname for hostnames in ip_to_root_domains.values() for hostname in hostnames])
    resolved_host_count = len(resolvable_host_names)
    logging.info('* count of unique hostnames (without subdomains): %s', f'{resolved_host_count:,}')
    # Count unresolvable hosts by reason
    unresolvable_counts = {}
    for reason in unresolvable_hosts:
        unresolvable_counts[reason] = unresolvable_counts.get(reason, 0) + 1

    # Sort by count descending
    sorted_reasons = sorted(unresolvable_counts.items(), key=lambda x: x[1], reverse=True)

    logging.info('* count of unresolvable hosts by reason:')
    for reason, count in sorted_reasons:
        logging.info('  - %s: %s', reason, f'{count:,}')
    logging.info('  - total: %s', f'{len(unresolvable_hosts):,}')
    logging.info('* count of hostnames with IP in allowlist: %s', f'{len(set(hostnames_with_ip_in_allowlist)):,}')
    logging.info('* count of hostnames with non-public IP: %s', f'{len(set(hostnames_with_non_public_ip)):,}')

    assert unique_host_count >= 0
    assert resolved_host_count >= 0
    assert resolved_host_count <= unique_host_count
    assert resolved_host_count >= min_resolved_host_count, f'{resolved_host_count:,} vs {min_resolved_host_count:,}'
    assert (len(unresolvable_hosts)/unique_host_count) <= 0.5, f'{len(unresolvable_hosts):,} is high relative to {unique_host_count:,}'

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


def canonicalize_hostnames(hostnames):
    """Simplify list of hostnames using ALIAS_MAP"""
    canonical = set()
    for h in hostnames:
        canonical.add(ALIAS_MAP.get(h, h))
    return sorted(canonical)


def resolve_and_filter_hostnames(hostname_only_list: list, hostname_ip_list: list,
                                  resolver_cache: dict = None, update_cache: bool = True,
                                  max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> tuple:
    """Resolve hostnames and filter IP results based on source.

    This function resolves two sets of hostnames:
    1. hostname_only_list: Hostnames where we want valid FQDNs but NOT their IPs
    2. hostname_ip_list: Hostnames where we want both valid FQDNs AND their IPs

    Args:
        hostname_only_list: List of hostnames that should not contribute IPs
        hostname_ip_list: List of hostnames that should contribute IPs
        resolver_cache: Optional cache of previous resolutions
        update_cache: Whether to update the cache with new resolutions
        max_concurrency: Maximum concurrent DNS queries

    Returns:
        tuple (valid_fqdns, ip_to_root_domains):
        - valid_fqdns: Set of all valid FQDNs from both lists
        - ip_to_root_domains: Dict mapping IPs to root domains, only from hostname_ip_list
    """
    # Combine both input sets for single resolution call
    combined_hostnames = list(set(hostname_only_list + hostname_ip_list))

    # Track which FQDNs came from hostname_ip_list for filtering
    # Convert to root domains for proper comparison
    hostname_ip_roots = set()
    for fqdn in hostname_ip_list:
        root_domain = get_root_domain(fqdn)
        hostname_ip_roots.add(root_domain)

    print('Resolving all hostnames...', flush=True)
    (valid_fqdns, all_ip_to_root_domains) = resolve_hosts(
        combined_hostnames, 0, resolver_cache=resolver_cache,
        update_cache=update_cache, max_concurrency=max_concurrency)

    # Filter ip_to_root_domains to only include IPs from hostnames that were in hostname_ip_list
    ip_to_root_domains = collections.defaultdict(set)
    for ip, root_domains in all_ip_to_root_domains.items():
        # Check if any of the root domains for this IP came from hostname_ip_list
        matching_domains = root_domains & hostname_ip_roots
        if matching_domains:
            # Only include the matching root domains for this IP
            ip_to_root_domains[ip] = matching_domains

    return (valid_fqdns, ip_to_root_domains)


def write_ips(ip_to_root_domains: dict, ips_only: dict, final_ip_fn: str = FINAL_IP_FN) -> None:
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

    # Make this message consistent to the hostname message.
    print(f'writing {len(sorted_ips):,} IPs to {final_ip_fn}')

    # Ensure output directory exists
    os.makedirs(os.path.dirname(final_ip_fn), exist_ok=True)

    with open(final_ip_fn, "w", encoding="utf-8") as output_file:
        output_file.write(f"# {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        for ip in sorted_ips:
            hostnames_list = canonicalize_hostnames(set(merged_dict[ip]))
            hostnames_str = ",".join(hostnames_list)
            output_file.write(f"{ip} # {hostnames_str}\n")


def download_and_load_resolver_cache(cache_url, cache_path):
    """Download and load resolver cache from R2"""
    print(f"Downloading resolver cache from {cache_url}")
    r = requests.get(cache_url, timeout=INDIVIDUAL_TIMEOUT_SECONDS)
    r.raise_for_status()
    with open(cache_path, 'wb') as f:
        f.write(r.content)
    with lzma.open(cache_path, 'rt', encoding='utf-8') as f:
        cache_data = json.load(f)
    host_to_results = cache_data.get('host_to_results', {})
    print(f"Loaded resolver cache with {len(host_to_results)} entries, created {cache_data['created_utc']}")
    return host_to_results


def write_resolver_cache(cache_path, host_to_results):
    """Write resolver cache to file"""
    data = {
        'created_utc': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'host_to_results': host_to_results
    }
    with lzma.open(cache_path, 'wt', encoding='utf-8') as f:
        json.dump(data, f)
    logging.info("Wrote resolver cache with %s entries to %s", f"{len(host_to_results):,}", cache_path)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Prepare final VPN/IP lists")
    parser.add_argument('--use-resolver-cache', action='store_true',
                        help='Use public R2 resolver cache for hostname resolution')
    parser.add_argument('--max-hostnames', type=int, default=None,
                        help='Limit the number of hostnames to process (for testing)')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_MAX_CONCURRENCY,
                        help='Maximum concurrent DNS queries (default: %s)' % DEFAULT_MAX_CONCURRENCY)
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)

    os.makedirs(os.path.dirname(LOCAL_CACHE_PATH), exist_ok=True)
    logging.info('Reading input hostnames...')

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

    if args.max_hostnames:
        print(f'Limiting to {args.max_hostnames:,} hostnames for testing...', flush=True)
        fqdns_to_resolve_no_ip_collection = random.sample(fqdns_to_resolve_no_ip_collection, min(
            args.max_hostnames, len(fqdns_to_resolve_no_ip_collection)))
        hostnames_ip = random.sample(hostnames_ip, min(args.max_hostnames, len(hostnames_ip)))
        update_cache = False

    # Use the new refactored function to handle hostname resolution and filtering
    (valid_fqdns, ip_to_root_domains) = resolve_and_filter_hostnames(
        fqdns_to_resolve_no_ip_collection, hostnames_ip,
        resolver_cache=resolver_cache, update_cache=update_cache,
        max_concurrency=args.max_concurrency)

    print('Reading IP inputs...', flush=True)
    ips_only = read_ips(IP_DIR)
    print('Writing outputs...', flush=True)
    write_ips(ip_to_root_domains, ips_only)

    pattern_checker = AdguardPatternChecker(all_patterns)
    fqdns_not_matching = fqdns_not_matching_pattern(valid_fqdns, pattern_checker)
    # Write patterns first, then non-matching FQDNs to Adguard file
    adguard_combined_list = sort_fqdns(all_patterns) + sort_fqdns(fqdns_not_matching)
    write_addresses_to_file(ADGUARD_OUTPUT_FN, adguard_combined_list, units='Adguard entries', write_timestamp=True)
    # Write all valid FQDNs to the final hostname file
    write_addresses_to_file(FINAL_HOSTNAME_FN, sort_fqdns(valid_fqdns), units='hostnames', write_timestamp=True)

    if update_cache:
        print('Writing resolver cache...', flush=True)
        write_resolver_cache(LOCAL_CACHE_PATH, resolver_cache)

    print(f"{sys.argv[0]} is done")


if __name__ == "__main__":
    main()
