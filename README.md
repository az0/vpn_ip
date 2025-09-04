# Network Addresses for VPN and Proxy Services

This repository contains lists of hostnames and IP addresses for various VPNs (e.g., ProtonVPN, Windscribe, Browsec, VeePN, Hoxx) as well as some proxies. The repository is useful for network administrators, security professionals, and security researchers.

This repository provides these lists:

* **hostname.txt**: A unique list of hostnames that have at least one valid IP address.
* **adguard.txt**: Like `hostname.txt` but in [Adguard format](https://adguard-dns.io/kb/general/dns-filtering-syntax/?utm_medium=ui) which significantly reduces file size while generalizing to new subdomain names.
* **ip.txt**: IP addresses only for the servers that actually serve as VPNs.

Efforts have been made to avoid blocking the IP addresses of general-purpose sites, currently Cloudflare and Shopify. If another non-VPN site is blocked, open an issue.

## How to use

For comprehensive blocking of VPNs, set up filtering at two levels.

First, use `hostname.txt` or `adguard.txt` to block hostname resolution at your DNS server (e.g., [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome), [Pi-hole](https://pi-hole.net/)). For use certain systems like dnsmasq or the Linux `/etc/hosts` file, you will need to convert it.

Second, use `ip.txt` in the router (e.g., ipset or OpenWRT ipban) to reject the forwarding based on IP address. 

### DNS bypass

A complementary approach is to manage DNS resolution at the network router:

* Block DNS resolution of known DNS resolvers (e.g., [hagezi's DNS bypass list](https://github.com/hagezi/dns-blocklists/?tab=readme-ov-file#bypass)).
* Reject forwarding to the IP addresses of DNS providers (e.g., [dibdot's DoH list](https://github.com/dibdot/DoH-IP-blocklists) with ipban).
* Reject forwarding of TCP and UDP ports 53 and 853 or redirect them to your DNS resolver.

## Download

View and download the latest data files here. Use the Download URL for automatic updates.

| File | Download URL |
|------|---------|
| `hostname.txt` | [Download](http://az0-vpnip-public.oooninja.com/hostname.txt) |
| `adguard.txt` | [Download](http://az0-vpnip-public.oooninja.com/adguard.txt) |
| `ip.txt` | [Download](http://az0-vpnip-public.oooninja.com/ip.txt) |

## Related

* [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn): IP addresses of VPN networks

## License

Copyright (C) 2023-2024 by Andrew Ziem.

This repository is licensed under the terms of the [GNU General Public License version 3 or later](LICENSE).
