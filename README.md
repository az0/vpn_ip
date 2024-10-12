# Network Addresses for VPNs

This repository contains lists of hostnames and IP addresses for ProtonVPN, Windscribe, Browsec, VeePN, Hoxx, and other VPNs, as well as some proxies.

This repository provides two lists:

* [hostname.txt](data/output/hostname.txt): A unique list of hostnames that have least one valid IP address
* [ip.txt](data/output/ip.txt): IP addresses only for the servers that actually serve as VPNs

Efforts have been made to avoid blocking the IP addresses of general-purpose sites, currently Cloudflare and Shopify. If another non-VPN site is blocked, open an issue.

## How to use

For comprehensive blocking of VPNs, use both files together.

First, use `hostname.txt` to block hostname resolution at your DNS server (e.g., [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome), [Pi-hole](https://pi-hole.net/)). The provided format is a simple list of hostnames, and for use in other systems like dnsmasq, you will need to convert it.

Second, use `ip.txt` in the router (e.g., ipset or OpenWRT ipban) to reject the forwarding based on IP address. 

### DNS bypass

A complementary approach is to manage DNS resolution:

* Block DNS resolution of DNS resolvers (e.g., [hagezi](https://github.com/hagezi/dns-blocklists/?tab=readme-ov-file#bypass)).
* Reject forwarding to the IP addresses of DNS providers (e.g., [dibdot](https://github.com/dibdot/DoH-IP-blocklists) with ipban).
* Reject forwarding of TCP and UDP ports 53 and 853 or redirect them to your DNS resolver.

## Related

* [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn): IP addresses of VPN networks

## License

Copyright (C) 2023, 2024 Andrew Ziem

This repository is licensed under the [LICENSE](GNU General Public License version 3 or later).
