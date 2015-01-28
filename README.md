# sdc-zonedns

This is a simple add-on for Joyent SmartDataCenter (SDC), which provides a DNS server that gives DNS names to ordinary VMs in an SDC cluster.

It can be deployed standalone, answering as an authoritative DNS server, or it can be a "hidden master", where slave NS (running ordinary BIND) use zone transfers (AXFR) to sync the DNS records from sdc-zonedns, and it is never exposed directly to the Internet.

There is also support for deploying a sub-domain to be used by a front-end reverse proxy, for cases where VMs are deployed on internal RFC1918 addresses and a reverse proxy provides vhosted access to websites on them from outside.
