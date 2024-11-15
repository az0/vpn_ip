#!/usr/bin/env python3
"""
Find hostnames from the Umbrella Popularity List that match a list of Adguard patterns
"""

import os
import requests
import time
import zipfile

from prepare_final_lists import read_hostnames_from_file, input_hostname_only_pattern, input_hostname_ip_pattern
from common import AdguardPatternChecker, adguard_input_fn, read_input_hostnames, sort_fqdns, write_hostnames_to_text_file

output_fn = 'data/input/hostname_only/cisco_umbrella.txt'
max_zip_file_age_days = 7


def get_cisco_umbrella():
    tmpdir = os.getenv('XDG_CACHE_HOME', os.getenv('TMPDIR', '/tmp'))
    fn = os.path.join(tmpdir, 'top-1m-cisco-umbrella.zip')
    if os.path.isfile(fn) and (time.time() - os.path.getmtime(fn)) > (max_zip_file_age_days * 24 * 60 * 60):
        print(f'deleting old file {fn}')
        os.remove(fn)

    if not os.path.isfile(fn):
        url = 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'
        print(f'downloading from {url} to {fn}')
        r = requests.get(url)
        with open(fn, 'wb') as file:
            file.write(r.content)

    with zipfile.ZipFile(fn, 'r') as zip_ref:
        zip_ref.extractall(path=tmpdir, members=['top-1m.csv'])

    with open(os.path.join(tmpdir, 'top-1m.csv'), 'r') as file:
        cisco_hostnames = [line.split(',')[1].strip() for line in file]

    print(f'read {len(cisco_hostnames):,} hostnames from top-1m.csv')
    return cisco_hostnames


def main():
    cisco_hostnames = get_cisco_umbrella()
    adguard_patterns = read_hostnames_from_file(adguard_input_fn)
    adguard_checker = AdguardPatternChecker(adguard_patterns)
    hostnames_matching_pattern = [hostname for hostname in cisco_hostnames if adguard_checker.check_fqdn(hostname)]
    prior_hostnames = read_input_hostnames(output_fn)
    export_hostnames = list(set(hostnames_matching_pattern) | set(prior_hostnames))
    write_hostnames_to_text_file(output_fn, sort_fqdns(export_hostnames))


if __name__ == '__main__':
    main()
    print('All done')
