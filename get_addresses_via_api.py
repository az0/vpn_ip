#!/usr/bin/env python3

"""
Get addresses via web service APIs and store in text files.

The configuration file is a JSON file.
"""

import json
import os
import sys
from urllib.parse import urlparse

import requests
from common import read_hostnames_from_file, write_addresses_to_file

HOSTNAME_IP_ROOT = 'data/input/hostname_ip/'
IP_ROOT = 'data/input/ip/'
JSON_CONFIG_FN = 'data/get_addresses_via_api.json'


def collect_hostnames_and_ips(url, hostname_key, ip_key):
    """Collect hostnames and IP addresses from an API URL"""
    assert isinstance(url, str)
    assert isinstance(hostname_key, (list, tuple))
    assert isinstance(ip_key, (list, tuple))
    print(f'reading {url}')
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        data = response.json()
        hostnames = []
        ips = set()
        process_json(data, hostnames, ips, hostname_key, ip_key)
        return hostnames, ips
    else:
        print(f"Failed to retrieve data from {url} with status code {response.status_code}")
        print(f"Response text: {response.text}")
        return (None, None)


def extract_hostname(address_source):
    """Extract hostname from input

    Input can be either a string or a list of strings.
    If a string is a URL, this returns just the hostname

    This returns a list of strings (even if input is a string).
    """
    if isinstance(address_source, str):
        # check if a URL like http: or a hostname like example.com
        if address_source.startswith('http'):
            parsed_url = urlparse(address_source)
            return (parsed_url.hostname,)
        else:
            return (address_source,)
    elif isinstance(address_source, list):
        ret = []
        for item in address_source:
            ret.extend(extract_hostname(item))
        return ret
    else:
        raise ValueError(f"Unexpected input type: {type(address_source)}")


def process_json(data, hostnames, ips, hostname_key, ip_key):
    """Recursively look for hostnames and IP addresses in JSON data"""
    assert isinstance(hostnames, list)
    assert isinstance(ips, set)
    assert isinstance(hostname_key, (list, tuple))
    assert isinstance(ip_key, (list, tuple))
    if isinstance(data, dict):
        for key, value in data.items():
            if key in hostname_key:
                hostnames.extend(extract_hostname(value))
            elif key in ip_key:
                ips.add(value)
            if isinstance(value, (dict, list)):
                process_json(value, hostnames, ips, hostname_key, ip_key)
    elif isinstance(data, list):
        for item in data:
            process_json(item, hostnames, ips, hostname_key, ip_key)


def process_service(service_code, service):
    """Process one service (e.g., WindScribe, ProtonVPN)"""
    print(f'processing {service_code}')
    hostname_fn = os.path.join(HOSTNAME_IP_ROOT, service_code+'_api.txt')
    ip_fn = os.path.join(IP_ROOT, service_code+'_api.txt')
    all_hostnames = set()
    all_ips = set()

    for url in service['urls']:
        new_hostnames, new_ips = collect_hostnames_and_ips(
            url, service['hostname_key'], service['ip_key'])
        if new_hostnames:
            all_hostnames.update(new_hostnames)
        if new_ips:
            all_ips.update(new_ips)

    print(f'read {len(all_hostnames)} hostnames and {len(all_ips)} IPs from API')

    print(f'hostname_fn={hostname_fn}')
    if os.path.exists(hostname_fn):
        (old_hostnames, old_patterns) = read_hostnames_from_file(hostname_fn)
        assert len(old_patterns) == 0
        old_hostnames = [
            hostname for hostname in old_hostnames if hostname not in all_hostnames]
        print(f'remembered {len(old_hostnames)} hostnames from {hostname_fn}')
        all_hostnames.update(old_hostnames)

    write_addresses_to_file(hostname_fn, sorted(all_hostnames))
    # FIXME later: sort IPs like prepare_final_lists.write_ips()
    write_addresses_to_file(ip_fn, sorted(all_ips), units="IP addresses")


def go():
    """Main entry point"""

    with open(JSON_CONFIG_FN, encoding='utf-8') as file:
        services = json.load(file)

    failed_services=[]
    success_count = 0
    for key in services.keys():
        try:
            process_service(key, services[key])
        except requests.exceptions.ConnectionError as e:
            print(f"exception processing service {key}: {e}")
            failed_services.append(key)
        except Exception as e:
            print(f"exception processing service {key}: {e}")
            failed_services.append(key)
        else:
            success_count += 1

    print(f"{success_count} services processed successfully")
    if failed_services:
        print(f"{len(failed_services)} services failed: {failed_services}")
        sys.exit(1)

    print(f"{sys.argv[0]} is done")


go()
