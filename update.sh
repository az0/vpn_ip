#!/bin/sh

python3 -V

pip install -r requirements.txt

if [ -n "${GITHUB_ACTIONS}" ]; then
    # Do not show progress bars in GitHub Actions.
    export TQDM_DISABLE=1
fi

echo "$(date): Running tests"
python3 -m unittest -v common get_browser_extension prepare_final_lists

# Execute all the steps in the scheduled GitHub action to
# update this repository

echo "$(date): Running get_addresses_via_api.py"
./get_addresses_via_api.py || exit 1

echo "$(date): Running get_browsec_github.py"
time timeout 3m ./get_browsec_github.py || exit 1

echo "$(date): Running get_browser_extension.py"
./get_browser_extension.py || exit 1

echo "$(date): Running get_cisco_umbrella.py"
./get_cisco_umbrella.py || exit 1

echo "$(date): Running get_pia.py"
./get_pia.py || exit 1

# tldextract does this automatically, but split it out to troubleshoot
# issue with script timeout.
echo "$(date): Running tldextract --update"
tldextract --update || exit 1
du -bcs $HOME/.cache/python-tldextract

# This step intermittently hung in GitHub Actions, so use unbuffered
# output and set a timeout.
echo "$(date): Running prepare_final_lists.py"
time timeout 10m python3 -u ./prepare_final_lists.py || exit 1

 echo "$(date): update.sh is done"