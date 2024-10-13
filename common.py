import glob
import os
import socket

INPUT_HOSTNAME_PATTERN = 'data/input/hostname_*/*.txt'

def add_new_hostnames_to_file(dst_fn, get_subdomains_func, *args):
    """
    Add new hostnames to a file.

    The file must already exist.
    """
    full_fn = os.path.join('data/input/hostname_ip', dst_fn)
    known_hostnames = read_hostnames_from_file(full_fn)
    print(f'* count of known hostnames: {len(known_hostnames)}')

    api_hostnames = get_subdomains_func(*args)
    print(f'* count of API hostnames: {len(api_hostnames)}')

    new_hostnames = set(api_hostnames) - set(known_hostnames)

    if not new_hostnames:
        print('* no new hostnames found')
        return

    print(f'* writing  {len(new_hostnames)} new hostnames to {full_fn}')
    with open(full_fn, 'a') as file:
        for hostname in sorted(new_hostnames):
            file.write(f'{hostname}\n')

def clean_line(line: str) -> str:
    """Remove comments and whitespace from line"""
    return line.strip('\n').split('#')[0].split(',')[0].strip()


def read_hostnames_from_file(filename: str) -> list:
    """Return every unique hostname from input file"""
    print(f'reading hosts from {filename}')
    hostnames = set()
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            hostname = clean_line(line)
            if '-tor.' in hostname:  # example: hostname=us-co-21-tor.protonvpn.net
                # print(f'WARNING: skipping tor: {hostname}')
                continue
            if hostname:
                hostnames.add(hostname)
    return list(hostnames)


def read_input_hostnames() -> list:
    """Return every unique hostname from input directory (multiple files)"""
    hostnames = set()
    for filename in glob.glob(INPUT_HOSTNAME_PATTERN):
        hostnames.update(read_hostnames_from_file(filename))
    return list(hostnames)


def resolve_hostname(hostname: str) -> list:
    """Return a list of IPv4 IPs for the given hostname

    If there is an error resolving the hostname, return an empty list

    """
    # print(f'INFO: resolving hostname {hostname}')
    try:
        ip_addresses = socket.getaddrinfo(
            hostname, None, family=socket.AF_INET)
    except socket.gaierror as e:
        # print(f"ERROR: Error resolving {hostname}: {e}")
        return []
    ret = {ip[4][0] for ip in ip_addresses}
    return list(ret)
