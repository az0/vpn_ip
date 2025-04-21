#!/usr/bin/env python3
"""
Extract hostnames from web browser extension

FIXME: use Adguard patterns to match *.vpnexample.com instead of vpnexample.com
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
import urllib.request
import zipfile

from common import add_new_hostnames_to_file

SKIP_HOSTNAMES = ("firefox.com", "android.com", "example.com", "httpstat.us", "www.root-servers.org")
# XPI_DATA: (url, dst_fn)
XPI_DATA = (("https://addons.mozilla.org/firefox/downloads/latest/browsec/latest.xpi",
            'browsec_manifest.txt'),)


def parse_whois_output(output: str, domain: str = None):
    """Parse WHOIS output"""
    assert isinstance(output, str)
    assert isinstance(domain, str) or domain is None
    info = {"domain": domain} if domain else {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "registrant_country": r"Registrant Country:\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
        "created": r"Creation Date:\s*(.+)",
        "status": r"Domain Status: (\w+) https://icann.org/epp#\w+"
    }
    for key, pat in patterns.items():
        if key == "name_servers":
            info[key] = [ns.lower() for ns in re.findall(pat, output)]
        elif key == "status":
            statuses = re.findall(pat, output)
            if "inactive" in statuses:
                info[key] = "inactive"
            else:
                info[key] = None
        else:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                info[key] = m.group(1).strip()
            else:
                info[key] = None
    return info


def get_whois_info(domain):
    """Get WHOIS information for a domain"""
    assert isinstance(domain, str)
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        output = result.stdout
    except Exception as e:
        return {"domain": domain, "error": str(e)}
    return parse_whois_output(output, domain)


def batch_whois(domains):
    """Get WHOIS information for a list of domains"""
    assert isinstance(domains, list)
    results = []
    for d in domains:
        print(f"Querying WHOIS for {d}...")
        info = get_whois_info(d)
        results.append(info)
    return results


def print_whois_comparison(results):
    """Print WHOIS information for a list of domains"""
    assert isinstance(results, list)
    print(f"{'Domain':<30} {'Registrar':<20} {'Country':<8} {'Created':<20} {'Name Servers'}")
    print("-"*100)
    for r in sorted(results, key=lambda x: (x.get('registrar') or '', x.get('registrant_country') or '', x.get('created') or '')):
        ns = ', '.join(r.get('name_servers') or [])
        print(f"{r['domain']:<30} {str(r.get('registrar') or ''):<20} {str(r.get('registrant_country') or ''):<8} {str(r.get('created') or ''):<20} {ns}")


def parse_connect_src_hosts(manifest_file):
    """Parse connect-src hosts from browser extension manifest"""
    assert isinstance(manifest_file, str)
    with open(manifest_file, 'r', encoding='utf-8') as f:
        manifest = json.load(f)
    csp = manifest.get("content_security_policy", "")
    match = re.search(r'connect-src ([^;]+);?', csp)
    if not match:
        return []
    hosts = match.group(1).split()
    cleaned = set()
    for h in hosts:
        original = h
        if h == 'http://*/api/test':
            continue
        # Remove protocol
        h = re.sub(r'^https?://', '', h)
        # Remove path like in http://*.httpstat.us/*
        h = h.split('/')[0]
        # Remove wildcard like in http://*.httpstat.us/*
        h = h.lstrip('*.')
        # Remove empty and special cases
        if not h or h in ("'self'", "https:", "http:", 'http', ' https', "*", ''):
            continue
        # Remove skipped domains
        skip_this = False
        for s in SKIP_HOSTNAMES:
            if h == s or h.endswith('.' + s):
                skip_this = True
                break
        if skip_this:
            continue
        print(f"Keeping {original} --> {h}")
        cleaned.add(h)
    return sorted(cleaned)


def main():
    """Main function"""
    for xpi_url, dst_fn in XPI_DATA:
        with tempfile.TemporaryDirectory() as tmpdir:
            xpi_path = os.path.join(tmpdir, "extension.xpi")
            manifest_path = os.path.join(tmpdir, "manifest.json")
            urllib.request.urlretrieve(xpi_url, xpi_path)
            with zipfile.ZipFile(xpi_path, 'r') as z:
                z.extract("manifest.json", path=tmpdir)
            hosts = parse_connect_src_hosts(manifest_path)
            results = batch_whois(hosts)
            print_whois_comparison(results)
            # match *.vpnexample.com
            add_new_hostnames_to_file(dst_fn, lambda hosts_arg=hosts: [f"||{host}^" for host in hosts_arg])


class TestBrowserExtensionExtractHosts(unittest.TestCase):
    def test_parse_connect_src_hosts(self):
        """Test parse_connect_src_hosts function."""
        manifest_data = {
            "content_security_policy": "default-src 'none'; connect-src 'self' https: http://example.com http://*.foo.com http://bar.com http://*/api/test;"
        }
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            json.dump(manifest_data, tf)
            tf.flush()
            tf.seek(0)
            hosts = parse_connect_src_hosts(tf.name)
        self.assertIn('foo.com', hosts)
        self.assertIn('bar.com', hosts)
        self.assertNotIn('example.com', hosts)
        self.assertNotIn('*/api/test', hosts)

    def test_parse_whois_output(self):
        """Test parse_whois_output() function."""
        sample_output = '''Registrar: Internet Domain Service BS Corp.
Registrant Country: BS
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: inactive https://icann.org/epp#inactive
Registry Registrant ID: Not Available From Registry
Creation Date: 2024-08-29T15:55:38Z
Name Server: NS-1145.AWSDNS-15.ORG
Name Server: Ns-1982.Awsdns-55.Co.Uk
Name Server: ns-468.awsdns-58.com
Name Server: NS-922.AWSDNS-51.NET
'''
        info = parse_whois_output(sample_output, 'dummy.com')
        self.assertEqual(info['registrar'], 'Internet Domain Service BS Corp.')
        self.assertEqual(info['registrant_country'], 'BS')
        self.assertIn('inactive', info.get('status', ''))
        self.assertIn('ns-1145.awsdns-15.org', info['name_servers'])
        self.assertIn('ns-922.awsdns-51.net', info['name_servers'])
        self.assertIn('ns-1982.awsdns-55.co.uk', info['name_servers'])
        self.assertIn('ns-468.awsdns-58.com', info['name_servers'])


if __name__ == "__main__":
    unittest.main(exit=False, verbosity=2)
    main()
