#!/bin/sh

python3 -V

pip install -r requirements.txt

# Execute all the steps in the scheduled GitHub action to
# update this repository

./get_addresses_via_api.py
./get_browsec_github.py
./hostname_to_ip.py
./collate_hostnames.sh
