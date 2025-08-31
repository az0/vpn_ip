"""
Common functions

# Explaination of the three allowlists

ALLOWLIST_IP_FN is a list of CIDR ranges that filters
IP addresses before they are written to data/output/ip.txt.

ALLOWLIST_HOSTNAME_ONLY_FN is a list of hostnames that filters
hostnames before they are written to data/output/hostname.txt.
If the hostname came from data/input/hostname, then its
IP address will not be resolved, so it will not be added
to data/output/ip.txt.

ALLOWLIST_HOSTNAME_IP_FN is a list of hostnames that are
resolved and filtered at both the hostname and IP address
level.

"""

# built-in imports
import datetime
import glob
import ipaddress
import os
import re
import sys
import tempfile
import unittest

# third-party imports

# Constants
ALLOWLIST_IP_FN = 'data/input/allowlist_ip.txt'
ALLOWLIST_HOSTNAME_IP_FN = 'data/input/allowlist_hostname_ip.txt'
ALLOWLIST_HOSTNAME_ONLY_FN = 'data/input/allowlist_hostname_only.txt'
TEST_HOSTNAMES_VALID = [
                        'cornell.edu',
                        'facebook.com',
                        'google.com',
                        'lencr.org',
                        'microsoft.com',
                        'mozilla.org',
                        'nasa.gov',
                        'npt.org',
                        'pki.goog',
                        ]

# Classes


class AdguardPatternChecker:
    """Check if a FQDN matches any of the Adguard patterns

    This code supports a subset of Adguard DNS syntax, which itself is
    a subset of the Adguard syntax used by browser ad blockers.

    https://adguard-dns.io/kb/general/dns-filtering-syntax/#adblock-style-syntax

    Supported special characters:
    * ||: matches the beginning of a hostname, including any subdomain.
    * ^: the separator character marks the end of a hostname.
    * |: a pointer to the beginning or the end of the hostname.

    Examples of supported patterns:
    * ||example.com^ matches example.com and sub.example.com
    * ample.org| matches example.org but not example.org.com
    * |example matches example.org but not test.example

    Not supported special characters:
    * @@ marker for exception
    * / for regex
    * asterisk (*) for wildcard
    * rule modifiers like ^$important
    * hosts syntax with IP address like 1.2.3.4 example.com
    """

    def __init__(self, patterns: list):
        """Initialize with precompiled regex patterns for supported syntax"""
        # Group patterns by type for more efficient checking
        self.domain_suffix_patterns = []
        self.exact_match_patterns = []
        self.starts_with_patterns = []
        self.ends_with_patterns = []

        # Extract domain parts from ||domain.com^ patterns for pre-filtering
        self.domain_suffixes = set()

        # Process each pattern only once during initialization
        for pattern_str in patterns:
            if any(char in pattern_str for char in '*/$@'):
                print(f"Warning: Skipping unsupported pattern (contains '*' or '/' or '@@' or '$'): {pattern_str}")
                continue

            try:
                if pattern_str.startswith('||') and pattern_str.endswith('^'):
                    # ||domain.com^ syntax
                    domain_part = pattern_str[2:-1]
                    domain_escaped = re.escape(domain_part)
                    final_regex = r'(?:^|\.)' + domain_escaped + r'$'
                    self.domain_suffix_patterns.append(re.compile(final_regex, re.IGNORECASE))

                    # Store domain part for pre-filtering
                    self.domain_suffixes.add(domain_part.lower())

                elif pattern_str.startswith('|') and pattern_str.endswith('|'):
                    # |pattern| syntax (exact match)
                    exact_match_part = pattern_str[1:-1]
                    pattern_escaped = re.escape(exact_match_part)
                    final_regex = r'^' + pattern_escaped + r'$'
                    self.exact_match_patterns.append(re.compile(final_regex, re.IGNORECASE))

                elif pattern_str.startswith('|'):
                    # |pattern syntax (starts with)
                    starts_with_part = pattern_str[1:]
                    pattern_escaped = re.escape(starts_with_part)
                    final_regex = r'^' + pattern_escaped
                    self.starts_with_patterns.append(re.compile(final_regex, re.IGNORECASE))

                elif pattern_str.endswith('|'):
                    # pattern| syntax (ends with)
                    ends_with_part = pattern_str[:-1]
                    pattern_escaped = re.escape(ends_with_part)
                    final_regex = pattern_escaped + r'$'
                    self.ends_with_patterns.append(re.compile(final_regex, re.IGNORECASE))

                elif pattern_str.startswith('/') and pattern_str.endswith('/'):
                    print(f"Warning: Skipping unsupported regex pattern: {pattern_str}")
                else:
                    # Handle potential plain hostnames or other unsupported formats
                    print(f"Warning: Skipping unsupported pattern format: {pattern_str}")
            except re.error as e:
                print(f"Warning: Invalid regex generated from pattern '{pattern_str}': {e}")
            except Exception as e:
                print(f"Warning: Error processing pattern '{pattern_str}': {e}")

    def check_fqdn(self, fqdn: str) -> bool:
        """Check if FQDN matches any of the precompiled patterns"""
        # Quick pre-filtering for domain suffix patterns
        fqdn_lower = fqdn.lower()

        if self.domain_suffix_patterns:
            for suffix in self.domain_suffixes:
                if fqdn_lower.endswith(suffix):
                    # Only check the relevant domain suffix patterns if prefix matches
                    for pattern in self.domain_suffix_patterns:
                        if pattern.search(fqdn):
                            return True
                    # If we got here, none of the domain patterns matched
                    break

        if self.exact_match_patterns:
            for pattern in self.exact_match_patterns:
                if pattern.search(fqdn):
                    return True

        if self.starts_with_patterns:
            for pattern in self.starts_with_patterns:
                if pattern.search(fqdn):
                    return True

        if self.ends_with_patterns:
            for pattern in self.ends_with_patterns:
                if pattern.search(fqdn):
                    return True

        return False


class Allowlist:
    """Check network addresses against allowlist

    The allowlist prevents addresses from being blocked by
    blocking them from being written to files under data/output.
    """

    def __init__(self):
        self.ip_allowlist = set()
        with open(ALLOWLIST_IP_FN, 'r', encoding='utf-8') as f:
            for line in f:
                line = clean_line(line)
                if not line:
                    continue
                self.ip_allowlist.add(line)
        self.hostname_allowlist = set()
        self._load_hostnames(ALLOWLIST_HOSTNAME_IP_FN, resolve=True)
        self._load_hostnames(ALLOWLIST_HOSTNAME_ONLY_FN, resolve=False)

    def _load_hostnames(self, filename, resolve):
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                hostname = clean_line(line)
                if not hostname or len(hostname) <= 5:
                    continue
                self.hostname_allowlist.add(hostname)
                if resolve:
                    # Skip IP resolution for allowlist loading to avoid dependencies
                    # IPs will be resolved when needed in the main processing
                    pass

    def check_hostname_in_allowlist(self, hostname: str) -> bool:
        """Return True if hostname is in allowlist"""
        assert isinstance(hostname, str)
        return hostname in self.hostname_allowlist

    def check_ip_in_ranges(self, ip: str) -> bool:
        """Return True if IP is in allowlist

        Returns False for loopback and private addresses.
        """
        assert isinstance(ip, str)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_private:
            return False
        for r in self.ip_allowlist:
            if ip_obj in ipaddress.ip_network(r):
                return True
        return False




class TestCommon(unittest.TestCase):
    """Test common functions"""


    def test_add_new_hostnames_to_file_existing(self):
        """Test add_new_hostnames_to_file() with existing file"""
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
            dst_fn = tmp_file.name
            # Create a file (not using add_new_hostnames_to_file)
            # with the initial hostnames.
            initial = ['host1.com', 'host2.com']
            with open(dst_fn, 'w', encoding='utf-8') as f:
                f.write('\n'.join(initial) + '\n')
            # Hostnames in the stub overlap with the initial file.

            def stub1(*args):
                return ['host2.com', 'host3.com', 'host4.com']
            add_new_hostnames_to_file(dst_fn, stub1)
            written, _ = read_hostnames_from_file(dst_fn)
            expected = initial + ['host3.com', 'host4.com']
            # assertCountEqual compares elements ignoring the order.
            # (It does not just count the number of elements.)
            self.assertCountEqual(written, expected)

            # This stub repeats the initial hostnames, so no changes.
            def stub2(*args):
                return initial.copy()
            add_new_hostnames_to_file(dst_fn, stub2)
            written, _ = read_hostnames_from_file(dst_fn)
            self.assertCountEqual(written, expected)

            # This stub returns nothing.
            def stub3(*args):
                return []
            add_new_hostnames_to_file(dst_fn, stub3)
            written, _ = read_hostnames_from_file(dst_fn)
            self.assertCountEqual(written, expected)

    def test_add_new_hostnames_to_file_new(self):
        """Test add_new_hostnames_to_file() with new file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            dst_fn = os.path.join(tmpdir, 'new.txt')
            # file does not exist scenario

            def stub4(*args):
                return ['a.com', 'b.com']
            add_new_hostnames_to_file(dst_fn, stub4)
            written, _ = read_hostnames_from_file(dst_fn)
            self.assertCountEqual(written, ['a.com', 'b.com'])

    def test_add_new_hostname_to_file_pattern(self):
        """Test adding the same pattern multiple times."""
        pattern = '||foo.com^'
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
            filepath = tmp_file.name
            add_new_hostnames_to_file(filepath, lambda: [pattern])
            add_new_hostnames_to_file(filepath, lambda: [pattern])
            add_new_hostnames_to_file(filepath, lambda: [pattern])
            tmp_file.seek(0)
            content = tmp_file.read()
        os.remove(filepath)
        self.assertEqual(content.count(pattern), 1)

    def test_allowlist(self):
        """Test Allowlist class"""
        allowlist = Allowlist()
        self.assertEqual(allowlist.check_hostname_in_allowlist('shop.proton.me'), True)
        self.assertEqual(allowlist.check_hostname_in_allowlist('protonvpn.com'), False)
        self.assertEqual(allowlist.check_hostname_in_allowlist(''), False)
        self.assertEqual(allowlist.check_ip_in_ranges('1.1.1.1'), True)
        self.assertEqual(allowlist.check_ip_in_ranges('2.2.2.2'), False)
        self.assertEqual(allowlist.check_ip_in_ranges('127.0.0.1'), False)
        self.assertEqual(allowlist.check_ip_in_ranges('0.0.0.0'), False)

    def test_check_fqdn_against_adguard(self):
        """Test AdguardPatternChecker"""
        test_cases = (
            ('blog.example.org', ['||example.org^'], True),
            ('example.org', ['||example.org^'], True),
            ('barexample.org', ['||example.org^'], False),
            ('example.com', ['||example.org^'], False),
            ('example.org.uk', ['||example.org^'], False),
            ('example.org', ['|example.org|'], True),
            ('example.org', ['ample.org|'], True),
            ('example.org.com', ['ample.org|'], False),
            ('example.org', ['|example'], True),
            ('test.example', ['|example'], False),

        )
        for fqdn, patterns, expected in test_cases:
            with self.subTest(fqdn=fqdn, patterns=patterns, expected=expected):
                adguard_checker = AdguardPatternChecker(patterns)
                self.assertEqual(adguard_checker.check_fqdn(fqdn), expected)

    def test_read_hostnames_from_file(self):
        """Test read_hostnames_from_file() function"""
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
            hostnames = ['example.com', 'www.example.com']
            patterns = ['||example.com^', '|example', 'example^']
            tmp_file.write('#comment\n\n'+'# comment\n'.join(hostnames + patterns) + '#comment\n')
            tmp_file.seek(0)
            (actual_hostnames, actual_patterns) = read_hostnames_from_file(tmp_file.name)
            self.assertCountEqual(actual_hostnames, sorted(hostnames))
            self.assertCountEqual(actual_patterns, sorted(patterns))


    def test_sort_fqdns(self):
        """Test sort_fqdns() function"""
        fqdns = ['blog.example.com', 'mail.example.com', 'api.example.org', 'docs.example.org']
        self.assertEqual(sort_fqdns(fqdns), fqdns)
        self.assertEqual(sort_fqdns(fqdns[::-1]), fqdns)
        self.assertEqual(sort_fqdns([]), [])
        adguard_list = ['||' + fqdn + '^' for fqdn in fqdns]
        self.assertEqual(sort_fqdns(adguard_list), adguard_list)
        self.assertEqual(sort_fqdns(adguard_list[::-1]), adguard_list)

    def test_write_addresses_to_file(self):
        """Test write_addresses_to_file() function"""
        with tempfile.NamedTemporaryFile(mode='w+', delete=True, delete_on_close=False) as tmp_file:
            tmp_file.close()
            addresses = ['a.example.com', 'b.example.com']
            write_addresses_to_file(tmp_file.name, addresses)
            original_filesize = os.path.getsize(tmp_file.name)
            (actual_hostnames, actual_patterns) = read_hostnames_from_file(tmp_file.name)
            self.assertCountEqual(actual_hostnames, sorted(addresses))
            self.assertEqual(actual_patterns, [])
            write_addresses_to_file(tmp_file.name, addresses)
            self.assertEqual(os.path.getsize(tmp_file.name), original_filesize)


# Functions


def add_new_hostnames_to_file(dst_fn, get_subdomains_func, *args):
    """
    Add new hostnames to a file.

    Args:
        dst_fn: Destination file name. File may exist or be new.
                If relative, use data/input/hostname_ip. Absolute
                paths are used for testing.
        get_subdomains_func: Function to get subdomains.
        *args: Arguments to pass to get_subdomains_func.

    New hostnames are appended to the file.
    """
    full_fn = dst_fn if os.path.isabs(dst_fn) else os.path.join('data/input/hostname_ip', dst_fn)
    if os.path.exists(full_fn):
        known_hostnames, known_patterns = read_hostnames_from_file(full_fn)
        known_items = set(known_hostnames) | set(known_patterns)
    else:
        known_items = set()
    print(f'* count of known items: {len(known_items)}')

    api_hostnames = get_subdomains_func(*args)
    print(f'* count of API hostnames: {len(api_hostnames)}')

    new_hostnames = set(api_hostnames) - known_items

    if not new_hostnames:
        print('* no new hostnames found')
        return

    print(f'* writing {len(new_hostnames)} new hostnames to {full_fn}')
    mode = 'a' if os.path.exists(full_fn) else 'w'
    with open(full_fn, mode, encoding="utf-8") as file:
        for hostname in sorted(new_hostnames):
            file.write(f'{hostname}\n')


def clean_line(line: str) -> str:
    """Remove comments and whitespace from line"""
    return line.strip('\n').split('#')[0].split(',')[0].strip()


def read_hostnames_from_file(filename: str) -> tuple[list[str], list[str]]:
    """Return unique hostnames and patterns from input file

    Patterns are automatically detected by the characters.

    Ignored:
    * Empty lines
    * Comments starting with #

    Previously '-tor.' was ignored, but now it is allowed.
    In ca-tor.prod.surfshark.com, tor refers to Toronto.
    """
    print(f'reading hosts and patterns from {filename}')
    hostnames = set()
    patterns = set()
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            item = clean_line(line)
            if not item:
                continue

            # Identify patterns by specific markers
            is_pattern = False
            if item.startswith('||') and item.endswith('^'):
                is_pattern = True
            elif item.startswith('|') and item.endswith('|'):
                is_pattern = True
            elif item.startswith('|'): # Check after the previous two | cases
                is_pattern = True
            elif item.endswith('^'): # Treat lines ending in ^ as patterns too
                is_pattern = True
            elif item.endswith('|'): # Treat lines ending in | as patterns too
                is_pattern = True

            if is_pattern:
                patterns.add(item)
            # If not identified as a pattern and contains '.', then treat as hostname.
            elif '.' in item:
                hostnames.add(item)
            # else: Ignore lines that are neither patterns nor likely hostnames (e.g., 'example')

    return sorted(hostnames), sorted(patterns)


def read_input_hostnames(input_hostname_pattern) -> tuple[list[str], list[str]]:
    """Return unique hostnames and patterns from multiple files

    input_hostname_pattern: glob pattern for input files
    """
    all_hostnames = set()
    all_patterns = set()
    for filename in glob.glob(input_hostname_pattern):
        file_hostnames, file_patterns = read_hostnames_from_file(filename)
        all_hostnames.update(file_hostnames)
        all_patterns.update(file_patterns)
    return list(all_hostnames), list(all_patterns)


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


def write_addresses_to_file(filename, addresses, units="addresses", write_timestamp=False):
    """
    Write addresses (hostnames or IPs) to a text file.

    The caller must sort the addresses.

    The file includes a header.
    """
    assert isinstance(filename, str)
    assert isinstance(addresses, list)
    assert isinstance(units, str)
    if len(addresses) == 0 and not os.path.exists(filename):
        print(f'no {units} to write to {filename}')
        return
    print(f'writing {len(addresses):,} {units} to {filename}')
    script_filename = os.path.basename(sys.argv[0])
    with open(filename, "w", encoding="utf-8") as file:
        file.write(f"# This file was automatically generated by {script_filename}\n")
        if write_timestamp:
            file.write(f"# Updated {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}\n")
        file.write('\n'.join(addresses))
        file.write('\n')
