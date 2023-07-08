#!/usr/bin/env python3

import json
import requests
import os

hostname_ip_root = 'data/input/hostname_ip/'
ip_root = 'data/input/ip/'


def collect_hostnames_and_ips(url, hostname_key, ip_key):
    print(f'reading {url}')
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        hostnames = []
        ips = set()
        process_json(data, hostnames, ips, hostname_key, ip_key)
        return hostnames, ips
    else:
        print(f"Failed to retrieve data from {url}")


def process_json(data, hostnames, ips, hostname_key, ip_key):
    if isinstance(data, dict):
        for key, value in data.items():
            if key in hostname_key:
                hostnames.append(value)
            elif key in ip_key:
                ips.add(value)
            if isinstance(value, (dict, list)):
                process_json(value, hostnames, ips, hostname_key, ip_key)
    elif isinstance(data, list):
        for item in data:
            process_json(item, hostnames, ips, hostname_key, ip_key)


def write_to_file(filename, data):
    with open(filename, "w") as file:
        file.write('\n'.join(data))
        file.write('\n')


def process_service(service_code, service):
    """Process one service (e.g., WindScribe, ProtonVPN)"""
    print(f'processing {service_code}')
    hostname_fn = os.path.join(hostname_ip_root, service_code+'_api.txt')
    ip_fn = os.path.join(ip_root, service_code+'_api.txt')
    all_hostnames = set()
    all_ips = set()

    for url in service['urls']:
        new_hostnames, new_ips = collect_hostnames_and_ips(
            url, service['hostname_key'], service['ip_key'])
        all_hostnames.update(new_hostnames)
        all_ips.update(new_ips)

    print(f'read {len(all_hostnames)} hostnames and {len(all_ips)} IPs from API')

    print(f'hostname_fn={hostname_fn}')
    with open(hostname_fn, 'r') as file:
        old_hostnames = file.read().splitlines()

    old_hostnames = [
        hostname for hostname in old_hostnames if hostname not in all_hostnames]
    print(f'remembered {len(old_hostnames)} hostnames from {hostname_fn}')
    all_hostnames.update(old_hostnames)

    write_to_file(hostname_fn, sorted(all_hostnames))
    write_to_file(ip_fn, sorted(all_ips))


def go():
    """Main entry point"""
    windscribe = {}
    windscribe['urls'] = [
        "https://assets.windscribe.com/serverlist/firefox/1/1",
        "https://assets.windscribe.com/serverlist/mob-v2/1/1",
        "https://assets.windscribe.com/serverlist/openvpn/1/1",
        "https://assets.windscribe.com/serverlist/desktop/1/1"]
    windscribe['hostname_key'] = [
        'hostname', 'wg_endpoint', 'ovpn_x509', 'dns_hostname']
    windscribe['ip_key'] = ['ping_ip', 'ip', 'ip2', 'ip3']

    protonvpn = {}
    protonvpn['urls'] = ["https://api.protonmail.ch/vpn/logicals", ]
    protonvpn['hostname_key'] = ['Domain', ]
    protonvpn['ip_key'] = ['EntryIP', 'ExitIP']

    services = {'windscribe': windscribe, 'protonvpn': protonvpn}

    for key in services.keys():
        process_service(key, services[key])


go()
