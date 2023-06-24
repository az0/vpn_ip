#!/usr/bin/env python3

import json
import requests

hostname_fn = 'data/input/hostname_ip/windscribe_api.txt'
ip_fn = 'data/input/ip/windscribe_api.txt'
urls = [
    "https://assets.windscribe.com/serverlist/firefox/1/1",
    "https://assets.windscribe.com/serverlist/mob-v2/1/1",
    "https://assets.windscribe.com/serverlist/openvpn/1/1",
    "https://assets.windscribe.com/serverlist/desktop/1/1"
]


def collect_hostnames_and_ips(url):
    print(f'reading {url}')
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        hostnames = []
        ips = set()
        process_json(data, hostnames, ips)
        return hostnames, ips
    else:
        print(f"Failed to retrieve data from {url}")


def process_json(data, hostnames, ips):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "hostname":
                hostnames.append(value)
            elif key.startswith("ip"):
                ips.add(value)
            if isinstance(value, (dict, list)):
                process_json(value, hostnames, ips)
    elif isinstance(data, list):
        for item in data:
            process_json(item, hostnames, ips)


def write_to_file(filename, data):
    with open(filename, "w") as file:
        file.write('\n'.join(data))
        file.write('\n')


def go():
    all_hostnames = set()
    all_ips = set()

    for url in urls:
        new_hostnames, new_ips = collect_hostnames_and_ips(url)
        all_hostnames.update(new_hostnames)
        all_ips.update(new_ips)

    write_to_file(hostname_fn, sorted(all_hostnames))
    write_to_file(ip_fn, sorted(all_ips))


go()
