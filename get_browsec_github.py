#!/usr/bin/env python3

import requests
import json
import sys
from urllib.parse import urlparse

from common import add_new_hostnames_to_file

URLS = [
    "https://gist.githubusercontent.com/brwinfo/c89223109562d96b6a3f3e51693b4d87/raw/ad632996ec4c5771361e5bbf8ee19028d5fd474c/development.json",
    "https://gist.githubusercontent.com/brwinfo/0d4c6d2ebbe6fd716a43f0ac9d37ce22/raw/54cb5eb4c9fdfc970a91ab4b5c3ae84bebf7932b/production.json",
    "https://gist.githubusercontent.com/brwinfo/57bb84e8dd5ba79059b76d7bd64cbadb/raw/6c3d376d5abfb72e7676cb2f6a98ba3226e95ed5/qa.json",
    "https://gist.githubusercontent.com/brwinfo/e5ce6af89e0519e5407407ada07b0cbb/raw/abda2f29f216f8defcdd915d6b4962af31258e59/staging.json",
    "https://gist.githubusercontent.com/brwinfo/d603e3d1bc7b98c96d4fe79b61da5b4c/raw/d4c9b9cc9e124fbbdf63d23581a223cd395a8ea6/qa3.json",
    "https://gist.githubusercontent.com/brwinfo/8b8d36b124ffa887f77f7e0551242da5/raw/472ce5e44cbd667f01bce17f5d451f89e3ed0b3e/qa2.json"

]


def get_hostnames(urls):
    hostnames = []

    for url in urls:
        try:
            response = requests.get(url)
            response.raise_for_status()

            data = response.json()

            for item in data:
                parsed_url = urlparse(item)
                hostnames.append(parsed_url.hostname)

        except Exception as e:
            print(f"Error fetching or processing {url}: {e}")

    return hostnames


def main():
    dst_fn = 'browsec_github.txt'
    add_new_hostnames_to_file(dst_fn, get_hostnames, URLS)
    print(f"{sys.argv[0]} is done")



main()
