#!/usr/bin/env python3
# Get subdomains using the SecurityTrails API
# Andrew Ziem, September 2024
import os

import requests
import requests_cache

from common import add_new_hostnames_to_file

ST_API_KEY = os.getenv('ST_API_KEY')
CACHE_EXPIRATION = 3600*24*30  # 30 days

if not ST_API_KEY:
    raise ValueError(
        'The environment variable ST_API_KEY is not set. See https://securitytrails.com/app/account/credentials')

requests_cache.install_cache(
    'securitytrails_subdomains_cache', backend='sqlite', expire_after=CACHE_EXPIRATION)


def get_subdomains(domain):
    """Get subdomains using the SecurityTrails API"""
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=true&include_inactive=false"

    headers = {
        "accept": "application/json",
        "APIKEY": ST_API_KEY
    }

    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 200:
        subdomains = response.json()['subdomains']
    else:
        raise ValueError(f"Error calling SecurityTrails API: {response.status_code}")
    return [f'{subdomain}.{domain}' for subdomain in subdomains]


def check_api_usage():
    """Check API usage"""
    url = "https://api.securitytrails.com/v1/account/usage"

    headers = {
        "accept": "application/json",
        "APIKEY": ST_API_KEY
    }

    with requests_cache.disabled():
        response = requests.get(url, headers=headers, timeout=30)

    print(f'API quota: {response.text}')


def main():
    """Main function"""
    domains = (('trafcfy.com', 'browsec.txt'),
               ('prmsrvs.com', 'browsec.txt'),
               ('frmdom.com', 'browsec.txt'),
               ('hola.org', 'hola.txt'),
               ('holax.io', 'hola.txt'),
               ('holavpn.net', 'hola.txt'),
               ('protonvpn.net',   'protonvpn.txt'),
               ('proton.me', 'protonvpn.txt'),
               ('windscribe.com', 'windscribe.txt'),
               ('whispergalaxy.com', 'windscribe.txt'),
               ('block-only-if-you-have-a-small-pee-pee.io', 'windscribe.txt'),
               ('totallyacdn.com', 'windscribe.txt'),
               ('deepstateplatypus.com', 'windscribe.txt'),
               ('staticnetcontent.com', 'windscribe.txt'),
               ('telleport.me', 'telleport.txt'),
               ('northghost.com', 'touchvpn.net'),
               )

    for domain, dst_fn in domains:
        print(f'processing {domain}')
        add_new_hostnames_to_file(dst_fn, get_subdomains, domain)

    check_api_usage()


if __name__ == '__main__':
    main()
