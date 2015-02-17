# sdc-zonedns

This is a simple add-on for Joyent SmartDataCenter (SDC), which provides a DNS server that gives DNS names to ordinary VMs in an SDC cluster.

It can be deployed standalone, answering as an authoritative DNS server, or it can be a "hidden master", where slave NS (running ordinary BIND) use zone transfers (AXFR) to sync the DNS records from sdc-zonedns, and it is never exposed directly to the Internet.

There is also support for deploying a sub-domain to be used by a front-end reverse proxy, for cases where VMs are deployed on internal RFC1918 addresses and a reverse proxy provides vhosted access to websites on them from outside.

## Hostnames for VMs

Hostnames are formed in the pattern `account-alias.vms.example.com` -- where `account` is the SDC account owning the VM, `alias` is the alias set by the user, and `vms.example.com` is the `base` value set in the sdc-zonedns configuration.

Additionally, when aliases are unique across the whole cluster, the hostname `alias.vms.example.com` will also be reserved for the VM. The first user who creates a VM with a given alias will have the `alias.vms.example.com` hostname reserved for them permanently. This is considered more a legacy feature than anything else, to aid with migrating from previously existing DNS records.

## Fallback records

You can provide "fallback records" in the form of an ordinary BIND zonefile. If zonedns can't resolve a name by looking at the SDC cluster and the VMs currently present, it will refer to this zonefile and serve whatever records are listed there.

This allows you to have additional names as well as the automatically generated ones kept in the zonefile and resolvable as normal.

## Configuration

Configuration is done in the form of `config.json`, in the root directory of sdc-zonedns. A sample configuration is provided in `config.json.sample`. You will need to fill out the first section, providing details about the domain to serve and the location of the machine running the zonedns service.

Then change all the URLs for accessing SDC services to the relevant values for your SDC installation. The machine running zonedns will need access to the SDC admin network.

## Reverse proxy support

If you have VMs that use RFC1918 private addresses, but want to be able to serve websites, you can put them behind a reverse proxy (such as nginx). To help with this, sdc-zonedns can provide a subdomain where the names of zones (in the same `account-alias` format) resolve to a CNAME to the reverse proxy if they are using an RFC1918 address.

If a VM is on a public IP address, then their record in the "public" subdomain will simply resolve to the VM's public IP, not the reverse proxy.

You can enable this mode by changing `enabled` under `reverseProxy` in `config.json`, and filling out the related fields there.

When in reverse proxy mode, zonedns will look for fallback records in zone files called `private.zone` and `public.zone` rather than `base.zone`.
