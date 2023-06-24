#!/bin/sh

# Execute all the steps in the scheduled GitHub action to
# update this repository

./get_protonvpn.py
./get_windscribe.py
./hostname_to_ip.py
./collate_hostnames.sh
