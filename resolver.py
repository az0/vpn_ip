#!/usr/bin/env python3
"""
Fast async DNS resolver using dnspython

This module provides async DNS resolution with the following features:
- Multiple DNS servers with automatic failover
- Connection pooling for performance
- Configurable concurrency
- Detailed error handling and statistics
- Progress tracking with tqdm


# Data structure

Each hostname has a dict with the following structure:
{
    "ips": ["ip1", "ip2", ...],
    "dns_duration_ms": 123.4,
    "error": None or error_code
}

Error codes
* NXDOMAIN: The hostname does not exist
* Timeout: No response from any server within the lifetime timeout.
* NoNameservers: All authoritative servers failed to respond.
* NoAnswer: The query succeeded but the requested record type is missing.
* EmptyLabel: The hostname is empty.
* DNSException: Other DNS error.
* Exception: Other error.

# Future directions

* Query IPv6 AAAA records.
* Query multiple DNS servers per hostname and union the IP addresses.

"""

import asyncio
import datetime
import ipaddress
import random
import time
import unittest
from typing import Dict, List

import dns.asyncresolver
import dns.exception
import dns.resolver
import tqdm

from common import TEST_HOSTNAMES_VALID

DNS_TIMEOUT = 5.0  # seconds
LIFETIME_TIMEOUT = DNS_TIMEOUT * 2
DNS_SERVERS = [
    '1.1.1.1',
    '1.0.0.1',
    '8.8.8.8',
    '8.8.4.4',
    '9.9.9.10',
    '149.112.112.10',
    '76.76.2.0'
]
ERROR_CODES = [
    "NXDOMAIN",
    "Timeout",
    "NoNameservers",
    "NoAnswer",
    "EmptyLabel",
    "DNSException",
    "Exception"
]


class AsyncResolver:
    """Async DNS resolver with connection pooling and error handling"""

    def __init__(self, max_concurrency: int):
        """Initialize resolver with specified concurrency limit"""
        self.max_concurrency = max_concurrency
        self.resolver = dns.asyncresolver.Resolver()
        shuffled_servers = DNS_SERVERS.copy()
        random.shuffle(shuffled_servers)
        self.resolver.nameservers = shuffled_servers
        print(f"Using DNS servers: {self.resolver.nameservers[:3]}")
        self.resolver.timeout = DNS_TIMEOUT
        self.resolver.lifetime = LIFETIME_TIMEOUT
        self.resolve_times = []

    async def _resolve_single_hostname(self, hostname: str) -> dict:
        """Resolve a single hostname and return result dictionary

        Returns: dict with structure documented in module docstring
        """
        start_time = time.time()

        error_map = {
            dns.name.EmptyLabel: "EmptyLabel",
            dns.resolver.NXDOMAIN: "NXDOMAIN",
            dns.resolver.LifetimeTimeout: "LifetimeTimeout",
            dns.resolver.NoNameservers: "NoNameservers",
            dns.resolver.NoAnswer: "NoAnswer",
            dns.exception.DNSException: "DNSException",
            Exception: "Exception"
        }
        try:
            answer = await self.resolver.resolve(hostname, 'A')
            ips = [str(rdata) for rdata in answer]
            error = None
        except tuple(error_map) as e:
            ips = []
            key = type(e)
            if key in error_map:
                error = error_map[key]
            else:
                error = "Exception"
        finally:
            resolve_time = time.time() - start_time
            self.resolve_times.append(resolve_time)
        return {
            "ips": ips,
            "dns_duration_ms": round(resolve_time * 1000, 1),
            "error": error
        }

    async def resolve_hostnames(self, hostnames: List[str]) -> Dict[str, dict]:
        """Resolve multiple hostnames concurrently

        Args:
            hostnames: List of hostnames to resolve

        Returns:
            Dictionary mapping hostname to result dict with structure documented in module docstring
        """
        if not hostnames:
            return {}

        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def resolve_with_semaphore(hostname: str) -> tuple:
            async with semaphore:
                result = await self._resolve_single_hostname(hostname)
                return hostname, result

        # Make hostnames unique while preserving the order.
        unique_hostnames = list(dict.fromkeys(hostnames))
        tasks = [resolve_with_semaphore(hostname) for hostname in unique_hostnames]

        results = {}
        with tqdm.tqdm(total=len(tasks), desc="Resolving hostnames") as pbar:
            for task in asyncio.as_completed(tasks):
                hostname, result = await task
                results[hostname] = result
                pbar.update(1)

        return results

    def get_statistics(self) -> dict:
        """Get resolution timing statistics

        Returns:
            dict with min, avg, p95, max times in milliseconds
        """
        if not self.resolve_times:
            return {
                'min_ms': 0.0,
                'avg_ms': 0.0,
                'p95_ms': 0.0,
                'max_ms': 0.0,
                'count': 0
            }

        times_ms = [t * 1000 for t in self.resolve_times]
        sorted_times = sorted(times_ms)

        p95_index = int(0.95 * len(sorted_times))
        if p95_index >= len(sorted_times):
            p95_index = len(sorted_times) - 1

        return {
            'min_ms': min(times_ms),
            'avg_ms': sum(times_ms) / len(times_ms),
            'p95_ms': sorted_times[p95_index],
            'max_ms': max(times_ms),
            'count': len(times_ms)
        }


def resolve_hostnames_sync(hostnames: List[str], max_concurrency: int) -> Dict[str, dict]:
    """Synchronous wrapper for async hostname resolution

    Args:
        hostnames: List of hostnames to resolve
        max_concurrency: Maximum concurrent DNS queries

    Returns:
        Dictionary mapping hostname to result dict
    """
    start_total_time = datetime.datetime.now()
    async def _async_resolve():
        resolver = AsyncResolver(max_concurrency=max_concurrency)
        return await resolver.resolve_hostnames(hostnames), resolver.get_statistics()

    results, stats = asyncio.run(_async_resolve())
    end_total_time = datetime.datetime.now()
    total_time = (end_total_time - start_total_time).total_seconds()
    rate = stats['count'] / total_time if total_time > 0 else 0

    print("DNS resolution completed:")
    print(f"* Total queries: {stats['count']:,}")
    print(f"* Total time: {total_time:.1f}s")
    if stats['count'] > 0:
        print(f"* Rate: {rate:.1f} resolutions/sec")
        print(f"* Timing stats: min={stats['min_ms']:.1f}ms, avg={stats['avg_ms']:.1f}ms, "
              f"p95={stats['p95_ms']:.1f}ms, max={stats['max_ms']:.1f}ms")

    return results


class TestResolver(unittest.TestCase):
    """Test DNS resolver functionality"""

    def assert_is_ipv4(self, value, msg=None):
        """Assert that a value is a valid IPv4 address"""
        try:
            ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            standard_msg = f"{value!r} is not a valid IPv4 address"
            self.fail(self._formatMessage(msg, standard_msg))

    def assert_is_result(self, value, msg=None):
        """Assert that a value is a valid entry in a result dict"""
        try:
            self.assertIsInstance(value, dict)
            self.assertIn('ips', value)
            self.assertIsInstance(value['ips'], list)
            for ip in value['ips']:
                self.assert_is_ipv4(ip)
            self.assertIn('error', value)
            self.assertIsInstance(value['error'], (str, type(None)))
            if value['error'] is not None:
                self.assertIn(value['error'], ERROR_CODES)
        except AssertionError:
            standard_msg = f"{value!r} is not a valid result dict"
            self.fail(self._formatMessage(msg, standard_msg))

    def test_resolve_real_hostnames(self):
        """Test resolving real hostnames"""
        for concurrency in (2, 10):
            results = resolve_hostnames_sync(TEST_HOSTNAMES_VALID, concurrency)
            for hostname in TEST_HOSTNAMES_VALID:
                result = results[hostname]
                self.assert_is_result(result)
                self.assertGreater(len(result['ips']), 0, f"No IPs for {hostname}")
                self.assertIsNone(result['error'])

    def test_resolve_nonexistent_hostname(self):
        """Test resolving non-existent hostnames"""
        hostnames = ['nonexistent-domain-that-should-not-exist-12345.com',
                     'invalid..hostname.com',
                     'org',
                     '.org',
                     '-example.org',
                     'example-.org',
                     'example..org'
                     ]
        results = resolve_hostnames_sync(hostnames, 10)
        self.assertEqual(len(results), len(hostnames))

        for hostname in hostnames:
            with self.subTest(hostname=hostname):
                result = results[hostname]
                self.assert_is_result(result)
                self.assertEqual(result['ips'], [])
                self.assertIsNotNone(result['error'])

    def test_multiple(self):
        """Test resolving one hostname into multiple IPs"""
        hostname = 'test-multiple.oooninja.com'
        results = resolve_hostnames_sync([hostname], 1)
        self.assertEqual(len(results), 1)
        result = results[hostname]
        self.assertIsNone(result['error'])
        self.assertEqual(len(result['ips']), 2)
        self.assertIn('192.0.2.2', result['ips'])
        self.assertIn('192.0.2.1', result['ips'])

    def test_bogon_hostname(self):
        """Test hostname that returns bogon IP"""
        hostname = 'badipaddress.oooninja.com'
        results = resolve_hostnames_sync([hostname], 1)
        self.assertEqual(len(results), 1)
        result = results[hostname]
        self.assertIsNone(result['error'])
        self.assertEqual(len(result['ips']), 1)
        self.assertIn('0.0.0.0', result['ips'])

    def test_txt_only_hostname(self):
        """Test hostname with only TXT record, no A record"""
        hostname = 'test-txt.oooninja.com'
        results = resolve_hostnames_sync([hostname], 1)
        self.assertEqual(len(results), 1)
        result = results[hostname]
        self.assertEqual(result['ips'], [])
        self.assertIn(result['error'], [None, 'NoAnswer'])

    def test_private_ip_hostname(self):
        """Test hostname that returns private IP"""
        hostname = 'test-192.oooninja.com'
        results = resolve_hostnames_sync([hostname], 1)
        self.assertEqual(len(results), 1)
        result = results[hostname]
        self.assertIsNone(result['error'])
        self.assertEqual(len(result['ips']), 1)
        self.assertIn('192.168.0.1', result['ips'])

    def test_empty_hostname_list(self):
        """Test with empty hostname list"""
        results = resolve_hostnames_sync([], 1)
        self.assertEqual(results, {})

    def test_duplicate_hostnames(self):
        """Test handling of duplicate hostnames"""
        hostnames = ['example.com'] * 20
        results = resolve_hostnames_sync(hostnames, 1)
        self.assertEqual(len(results), 1)
        self.assertIn('example.com', results)


if __name__ == '__main__':
    unittest.main()
