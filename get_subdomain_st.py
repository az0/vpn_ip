# Get subdomains using the SecurityTrails API
# Andrew Ziem, September 2024
import requests
import requests_cache
import os

ST_API_KEY = os.getenv('ST_API_KEY')
cache_expiration = 3600*24*30  # 30 days

if not ST_API_KEY:
    raise ValueError(
        'The environment variable ST_API_KEY is not set. See https://securitytrails.com/app/account/credentials')

requests_cache.install_cache(
    'securitytrails_subdomains_cache', backend='sqlite', expire_after=cache_expiration)


def get_subdomains(domain):
    """Get subdomains using the SecurityTrails API"""
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=true&include_inactive=false"

    headers = {
        "accept": "application/json",
        "APIKEY": ST_API_KEY
    }

    response = requests.get(url, headers=headers)
    subdomains = response.json()['subdomains']
    return [f'{subdomain}.{domain}' for subdomain in subdomains]


def read_known_hostnames(txt_fn):
    """
    Read the known hostnames from a file.

    This ignores blank and commented lines.
    """
    if not os.path.exists(txt_fn):
        raise ValueError(f'{txt_fn} does not exist')

    with open(txt_fn, 'r') as file:
        known_hostnames = [
            line.strip() for line in file if line.strip() and not line.startswith('#')]

    return known_hostnames


def add_new_hostnames_to_file(domain, dst_fn):
    """
    Add new hostnames to a file.

    The file must already exist.
    """
    full_fn = os.path.join('data/input/hostname_ip', dst_fn)
    known_hostnames = read_known_hostnames(full_fn)
    print(f'* count of known hostnames: {len(known_hostnames)}')

    api_hostnames = get_subdomains(domain)
    print(f'* count of API hostnames: {len(api_hostnames)}')

    new_hostnames = set(api_hostnames) - set(known_hostnames)

    if not new_hostnames:
        print('* no new hostnames found')
        return

    print(f'* writing  {len(new_hostnames)} new hostnames to {full_fn}')
    with open(full_fn, 'a') as file:
        for hostname in sorted(new_hostnames):
            file.write(f'{hostname}\n')


def check_api_usage():

    url = "https://api.securitytrails.com/v1/account/usage"

    headers = {
        "accept": "application/json",
        "APIKEY": ST_API_KEY
    }

    with requests_cache.disabled():
        response = requests.get(url, headers=headers)

    print(f'API quota: {response.text}')


def main():
    domains = (('trafcfy.com', 'browsec.txt'),
               ('prmsrvs.com', 'browsec.txt'),
               ('hola.org', 'hola.txt'),
               ('holax.io', 'hola.txt'),
               ('holavpn.net', 'hola.txt'),
               ('protonvpn.net',   'protonvpn.txt'),
               ('proton.me', 'protonvpn.txt'),
               ('windscribe.com', 'windscribe.txt'),
               ('whispergalaxy.com', 'windscribe.txt'),
               ('telleport.me', 'telleport.txt'),
               )

    for domain, dst_fn in domains:
        print(f'processing {domain}')
        add_new_hostnames_to_file(domain, dst_fn)

    check_api_usage()


main()
