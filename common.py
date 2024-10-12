import glob
import socket

INPUT_HOSTNAME_PATTERN = 'data/input/hostname_*/*.txt'


def clean_line(line: str) -> str:
    """Remove comments and whitespace from line"""
    return line.split('#')[0].split(',')[0].strip()


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
