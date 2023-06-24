#!/usr/bin/env python3
import requests
import json

url ="https://api.protonmail.ch/vpn/logicals"
output_file = 'data/input/hostname_ip/protonvpn_api.txt'

response = requests.get(url)
data = json.loads(response.text)

domains0 = []
for server in data['LogicalServers']:
    if 'Domain' in server:
        domain = server['Domain']
        domains0.append(domain)

print(f'extracted {len(domains0)} domains from {url}')

with open(output_file, "w") as file:
    domains1 = set(domains0)
    for domain in sorted(domains1):
        file.write(f'{domain}\n')

print(f"{len(domains1)} domains written to {output_file}")

