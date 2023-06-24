#!/usr/bin/env python3
import requests
import json

url = "https://api.protonmail.ch/vpn/logicals"
output_file_hostname = 'data/input/hostname_ip/protonvpn_api.txt'
output_file_ip = 'data/input/ip/protonvpn_api.txt'

response = requests.get(url)
data = json.loads(response.text)

domains0 = []
ips0 = []
for l_server in data['LogicalServers']:
    if 'Domain' in l_server:
        domain = l_server['Domain']
        domains0.append(domain)
    if 'Servers' in l_server:
        for server in l_server['Servers']:
            ips = [server[key]
                   for key in server if key in ('EntryIP', 'ExitIP')]
            ips0.extend(ips)

print(f'extracted {len(domains0)} domains and {len(ips0)} IPs from {url}')

with open(output_file_hostname, 'r') as file:
    old_domains = file.read().splitlines()

old_domains = [domain for domain in old_domains if domain not in domains0]

print(f'remembered {len(old_domains)} domains from {output_file_hostname}')

domains0.extend(old_domains)

with open(output_file_hostname, "w") as file:
    domains1 = set(domains0)
    for domain in sorted(domains1):
        file.write(f'{domain}\n')
    print(f"{len(domains1)} domains written to {output_file_hostname}")

with open(output_file_ip, "w") as file:
    ips1 = set(ips0)
    for ip in sorted(ips1):
        file.write(f'{ip}\n')
    print(f"{len(ips1)} IPs written to {output_file_ip}")
