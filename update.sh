#!/bin/sh

# Execute all the steps in the scheduled GitHub action to
# update this repository

./get_addresses_via_api.py
./hostname_to_ip.py
./collate_hostnames.sh
