#!/usr/bin/env python3

# thanks some to ChatGPT

import socket
import collections
import ipaddress


in_fn = 'data/hostname.txt' # one host name per line
int_fn ='data/hostname_ip0.txt' # intermediate, contains duplicate IPs
final_fn = 'data/hostname_ip1.txt' # final, one line per IP, no duplicate IPs

# https://www.cloudflare.com/en-gb/ips/
def check_ip_in_ranges(ip):
    ranges = (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22"
    )
    for r in ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
            return True
    return False


# Open the input file for reading
with open(in_fn, "r") as input_file:
    # Open the output file for writing
    with open(int_fn, "w") as output_file:
        # Loop over each line in the input file
        for line in input_file:
            # Strip off any leading or trailing whitespace
            line = line.strip()
            # Skip any lines that start with a hash symbol (comment)
            if line.startswith("#"):
                continue
            hostname = line.split('#')[0] # remove comment at end
            hostname = line.split(',')[0]
            if not len(hostname) > 5:
                continue
            if '-tor.' in hostname: #example: hostname=us-co-21-tor.protonvpn.net
                print(f'WARNING: skipping tor: {hostname}')
                continue
            # Attempt to resolve the hostname to an IP address
            print (f'INFO: hostname={hostname}')
            try:
                ip_addresses = socket.getaddrinfo(hostname, None)
            except socket.gaierror as e:
                print(f"ERROR: Error resolving {hostname}: {e}")
                continue
            # Loop over each IP address and write it to the output file
            for ip_address in ip_addresses:
                ip_addr = ip_address[4][0]
                if check_ip_in_ranges(ip_addr):
                    print(f'WARNING: in whitelist {ip_addr} = {hostname}')
                    continue
                output_file.write(f'{ip_addr} # {hostname}\n')




# Open the input file for reading
with open(int_fn, "r") as input_file:
    # Read the lines into a list
    lines = input_file.readlines()

# Define a dictionary to hold the IP addresses and hostnames
ip_to_hostnames = collections.defaultdict(set)

# Loop over the lines and add each IP address and hostname to the dictionary
for line in lines:
    ip, _, hostname = line.strip().partition(" # ")
    ip_to_hostnames[ip].add(hostname)

# Sort the IP addresses
sorted_ips = sorted(ip_to_hostnames.keys(), key=lambda ip: int(ipaddress.ip_address(ip)))

# Open the output file for writing
with open(final_fn, "w") as output_file:
    # Loop over the sorted IP addresses and write each one to the output file
    for ip in sorted_ips:
        hostnames = ",".join(sorted(ip_to_hostnames[ip]))
        output_file.write(f"{ip} # {hostnames}\n")

