#!/bin/sh

python3 -V

pip install -r requirements.txt

if [ -n "${GITHUB_ACTIONS}" ]; then
    # Do not show progress bars in GitHub Actions.
    export TQDM_DISABLE=1
fi

# Execute all the steps in the scheduled GitHub action to
# update this repository

echo "$(date): Running get_addresses_via_api.py"
./get_addresses_via_api.py || exit 1

echo "$(date): Running get_browsec_github.py"
time timeout 3m ./get_browsec_github.py || exit 1

echo "$(date): Running prepare_final_lists.py"
./prepare_final_lists.py || exit 1

 echo "$(date): update.sh is done"