#!/usr/bin/env python3
"""
Find hostnames from the Umbrella Popularity List that match a list of Adguard patterns
"""

import os
import time
import zipfile

import requests
from tqdm import tqdm

from common import (
    AdguardPatternChecker, Allowlist,
    read_input_hostnames,
    read_hostnames_from_file, sort_fqdns, write_addresses_to_file
)
from prepare_final_lists import (
    INPUT_HOSTNAME_ONLY_PATTERN, INPUT_HOSTNAME_IP_PATTERN, FINAL_HOSTNAME_FN
)

OUTPUT_FN = 'data/input/hostname_only/cisco_umbrella.txt'
MAX_ZIP_FILE_AGE_DAYS = 7


def get_cisco_umbrella():
    """Download and extract the list"""
    tmpdir = os.getenv('XDG_CACHE_HOME', os.getenv('TMPDIR', '/tmp'))
    fn = os.path.join(tmpdir, 'top-1m-cisco-umbrella.zip')
    if os.path.isfile(fn) and (time.time() - os.path.getmtime(fn)) > (MAX_ZIP_FILE_AGE_DAYS * 24 * 60 * 60):
        print(f'deleting old file {fn}')
        os.remove(fn)

    if not os.path.isfile(fn):
        url = 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'
        print(f'downloading from {url} to {fn}')
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        with open(fn, 'wb') as file:
            file.write(r.content)

    with zipfile.ZipFile(fn, 'r') as zip_ref:
        zip_ref.extractall(path=tmpdir, members=['top-1m.csv'])

    with open(os.path.join(tmpdir, 'top-1m.csv'), 'r', encoding='utf-8') as file:
        cisco_hostnames = [line.split(',')[1].strip() for line in file]

    print(f'read {len(cisco_hostnames):,} hostnames from top-1m.csv')
    return cisco_hostnames


def get_all_patterns():
    """Read patterns from all input files"""
    _hostnames_only, patterns_only = read_input_hostnames(INPUT_HOSTNAME_ONLY_PATTERN)
    _hostnames_ip, patterns_ip = read_input_hostnames(INPUT_HOSTNAME_IP_PATTERN)
    return list(set(patterns_only) | set(patterns_ip))


def filter_umbrella_hostnames(cisco_hostnames):
    """Filter hostnames based on patterns and write to file"""
    adguard_patterns = get_all_patterns()
    adguard_checker = AdguardPatternChecker(adguard_patterns)
    hostnames_matching_pattern = []
    for hostname in tqdm(cisco_hostnames, desc="Filtering hostnames"):
        # Do not add example.com if ||example.com^ is a known pattern.
        if adguard_checker.check_fqdn(hostname) and not f"||{hostname}^" in adguard_patterns:
            hostnames_matching_pattern.append(hostname)
    if os.path.exists(OUTPUT_FN):
        prior_hostnames, _ = read_hostnames_from_file(OUTPUT_FN)
    else:
        prior_hostnames = []
    export_hostnames = list(set(hostnames_matching_pattern) | set(prior_hostnames))
    allowlist = Allowlist()
    export_hostnames = [
        hostname for hostname in export_hostnames if not allowlist.check_hostname_in_allowlist(hostname)]
    write_addresses_to_file(OUTPUT_FN, sort_fqdns(export_hostnames))


def analyze_overlap(cisco_hostnames):
    """Analyze overlap with final list"""
    final_hostnames, _ = read_hostnames_from_file(FINAL_HOSTNAME_FN)
    print(f'count of final hostnames: {len(final_hostnames):,}')
    keep_top = 2000
    cisco_top_1k = cisco_hostnames[:keep_top]
    overlap = [hostname for hostname in cisco_top_1k if hostname in final_hostnames]
    print(f'Overlap Umbrella {keep_top} vs final list: {len(overlap):,} hostnames')
    if overlap:
        print('The first 10 overlap hostnames are:')
        print(overlap[:10])


def main():
    """Main function"""
    cisco_hostnames = get_cisco_umbrella()
    filter_umbrella_hostnames(cisco_hostnames)
    analyze_overlap(cisco_hostnames)


if __name__ == '__main__':
    main()
    print('All done')
