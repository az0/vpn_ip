import os

def add_new_hostnames_to_file(dst_fn, get_subdomains_func, *args):
    """
    Add new hostnames to a file.

    The file must already exist.
    """
    full_fn = os.path.join('data/input/hostname_ip', dst_fn)
    known_hostnames = read_known_hostnames(full_fn)
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

