#!/usr/bin/env python3


import requests
import os
from urllib.parse import urlparse

hostname_ip_root = 'data/input/hostname_ip/'
ip_root = 'data/input/ip/'


def collect_hostnames_and_ips(url, hostname_key, ip_key):
    """Collect hostnames and IP addresses from an API URL"""
    assert isinstance(url, str)
    assert isinstance(hostname_key, (list, tuple))
    assert isinstance(ip_key, (list, tuple))
    print(f'reading {url}')
    response = requests.get(url)
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


def extract_hostname(input):
    """Extract hostname from input

    Input can be either a string or a list of strings.
    If a string is a URL, this returns just the hostname

    This returns a list of strings (even if input is a string).
    """
    if isinstance(input, str):
        # check if a URL like http: or a hostname like example.com
        if input.startswith('http'):
            parsed_url = urlparse(input)
            return (parsed_url.hostname,)
        else:
            return (input,)
    elif isinstance(input, list):
        ret = []
        for item in input:
            ret.extend(extract_hostname(item))
        return ret
    else:
        raise ValueError(f"Unexpected input type: {type(input)}")


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


def write_to_file(filename, data):
    with open(filename, "w", encoding="utf-8") as file:
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
        if new_hostnames:
            all_hostnames.update(new_hostnames)
        if new_ips:
            all_ips.update(new_ips)

    print(f'read {len(all_hostnames)} hostnames and {len(all_ips)} IPs from API')

    print(f'hostname_fn={hostname_fn}')
    if os.path.exists(hostname_fn):
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
    
    network_dd_vpn = {}
    network_dd_vpn['urls'] = (
        'https://softnour.com/Product/vpn/data.php',
    )
    network_dd_vpn['hostname_key'] = ( )
    network_dd_vpn['ip_key'] = ('host', )

    protonvpn = {}
    protonvpn['urls'] = ["https://api.protonmail.ch/vpn/logicals", ]
    protonvpn['hostname_key'] = ['Domain', ]
    protonvpn['ip_key'] = ['EntryIP', 'ExitIP']

    # NordVPN is deprecated 2024-09-08
    # nordvpn = {}
    # nordvpn['urls'] = ["https://nordvpn.com/api/server", ]
    # nordvpn['hostname_key'] = ['domain', ]
    # nordvpn['ip_key'] = ['ip_address', ]

    setupvpn = {}
    setupvpn['urls'] = [
        "https://tierbase3.fra1.cdn.digitaloceanspaces.com/tierssv.json",
        "https://tierbase4.s3.amazonaws.com/tierssv.json",
        "https://pub-8029ed10cf4e4db0b3757e6b82ef7a40.r2.dev/tierssv.json",
        "https://ams1.vultrobjects.com/tierupdate2/tierssv.json",
        "https://mirror4.es-mad-1.linodeobjects.com/tierssv.json",
        "https://raw.githubusercontent.com/the7c/update/master/master/ui/data.json",
        "https://bitbucket.org/the7c/update/raw/master/edge/pub/data.json"]
    setupvpn['hostname_key'] = ('uibase', 'mainbase', 'tierbase')
    setupvpn['ip_key'] = ()

    windscribe = {}
    windscribe['urls'] = [
        "https://assets.windscribe.com/serverlist/firefox/1/1",
        "https://assets.windscribe.com/serverlist/mob-v2/1/1",
        "https://assets.windscribe.com/serverlist/openvpn/1/1",
        "https://assets.windscribe.com/serverlist/desktop/1/1"]
    windscribe['hostname_key'] = [
        'hostname', 'wg_endpoint', 'ovpn_x509', 'dns_hostname']
    windscribe['ip_key'] = ['ping_ip', 'ip', 'ip2', 'ip3']

    services = {'network_dd_vpn': network_dd_vpn,
                'protonvpn': protonvpn,
                'setupvpn': setupvpn,
                'windscribe': windscribe}

    for key in services.keys():
        process_service(key, services[key])


go()
