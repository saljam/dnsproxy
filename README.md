A DNS server/poor person's NAT/tunneling tool combo. A hack to tunnel traffic for a network device that doesn't natively support VPN or SOCKS, but lets you choose the DNS server. It does this by responding to DNS queries with 'fake' IP addresses that are actually assigned to the machine running this code, then proxying the traffic to its original destination.

It's not as good as having a normal IPSEC tunnel and just routing traffic through that, but after a couple of hours wrestling with Strongswan config and XFRM policies I figured this was easier. Plus, once I got the idea I wanted to know if it'll work!

### Usage

- (Optionally) run the remote part of the tunnel.

        $ ssh remote-server
        remote-server$ dnsproxy -remote -tunnel-addr :5556

- Assign a bunch of IP addresses to the local machine. On OS X this could be:

        for addr in 192.168.1.{64..127}; do sudo ifconfig en0 add $addr; done

- Run dnsproxy, in this case forwarding ports 80 and 443.

        sudo dnsproxy -iprange 192.168.1.64/26 -port 80 -port 443  # add "-tunnel-addr remote-server:5556" if we're tunnelling.

### Warning

This is not secure. The traffic is not encrypted and there is no auth. If you're actually using this I recommend that you take measures to secure it, e.g. use TLS and have some kind IP address whitelist on your firewall.

### Things that would be nice to have

- Encryption
- Auth/IP address whitelist
- UDP support
- IPv6 support
- Parse `nmap` style IP address ranges
- Multiplex connections over a single tunnel. Maybe use http2?
