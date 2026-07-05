# SELinux policy (RHEL 9)

CloudFlow ships a targeted-policy module for each of its five daemons so they
run confined on RHEL 9 (and compatible distributions) with SELinux in
`enforcing` mode. Each daemon gets its own domain and its own private config
type, so the sandbox is least-privilege per service — the DHCP source cannot
read the ClickHouse sink's credentials, a sink cannot open a raw capture
socket, and none of them can write to disk.

This complements the systemd sandbox (`ProtectSystem=strict`, seccomp,
capability bounding — see each unit and its README): systemd confines the
*syscall and filesystem* surface, SELinux confines the *type-enforced access*
surface. They are independent layers.

## Modules

Each module lives next to the service it confines, mirroring the `systemd/`
layout:

```text
sources/cloudflow-source-dhcp/selinux/    cloudflow_source_dhcp
sources/cloudflow-source-dns/selinux/     cloudflow_source_dns
sinks/cloudflow-sink-splunk/selinux/      cloudflow_sink_splunk
sinks/cloudflow-sink-splunk-metrics/selinux/  cloudflow_sink_splunk_metrics
sinks/cloudflow-sink-clickhouse/selinux/  cloudflow_sink_clickhouse
```

A module is three files: `<name>.te` (type enforcement), `<name>.fc` (file
contexts), and a `Makefile` that includes the distribution's policy-devel
Makefile.

## What each domain is allowed

| Domain | Capabilities | Sockets | Egress | Config it can read |
|---|---|---|---|---|
| `cloudflow_source_dhcp_t` | `net_raw`, `sys_nice` | AF_PACKET ring, TCP client | Redis | `dhcp-source.yaml` |
| `cloudflow_source_dns_t` | `net_raw`, `sys_nice` | AF_PACKET ring, TCP client | Redis | `dns-source.{yaml,env}` |
| `cloudflow_sink_splunk_t` | none | TCP client | Redis, HTTPS (HEC) | `splunk-sink.{yaml,env}` |
| `cloudflow_sink_splunk_metrics_t` | none | TCP client | Redis, HTTPS (HEC) | `splunk-metrics.{yaml,env}` |
| `cloudflow_sink_clickhouse_t` | none | TCP client | Redis, HTTPS (ClickHouse) | `clickhouse-sink.{yaml,env}` |

Common to every domain: resolve names (`sysnet_dns_name_resolve`), connect to a
`redis_port_t` (6379), read its own config, and log to journald over the
inherited stderr fd. No domain is granted any file-write access — the
dead-letter path is a Redis stream (`XADD`), not a local spool, so the daemons
write nothing to disk.

Sources additionally get the AF_PACKET capture ring (`self:packet_socket` +
`net_raw`) and best-effort `SCHED_FIFO` (`sys_nice` + `self:process setsched`).
Sinks additionally get outbound HTTPS to `http_port_t` and read the system TLS
trust store (`miscfiles_read_generic_certs`) and `/dev/urandom` for libcurl /
OpenSSL.

## Prerequisites

```sh
sudo dnf install -y selinux-policy-devel   # provides /usr/share/selinux/devel/Makefile
getenforce                                 # expect Enforcing (or Permissive during rollout)
```

The binaries are assumed installed at `/usr/local/bin/cloudflow-*` and configs
under `/etc/cloudflow/` (the paths the systemd units use). If you install
elsewhere, adjust each module's `.fc` before building.

## Build and install

Build and install one module (repeat per service, or script the loop):

```sh
cd sources/cloudflow-source-dhcp/selinux
make                                        # -> cloudflow_source_dhcp.pp
sudo semodule -i cloudflow_source_dhcp.pp
sudo restorecon -Rv /usr/local/bin/cloudflow-source-dhcp /etc/cloudflow
```

All five at once from the repo root:

```sh
for d in sources/cloudflow-source-dhcp sources/cloudflow-source-dns \
         sinks/cloudflow-sink-splunk sinks/cloudflow-sink-splunk-metrics \
         sinks/cloudflow-sink-clickhouse; do
    make -C "$d/selinux"
    sudo semodule -i "$d"/selinux/*.pp
done
sudo restorecon -Rv /usr/local/bin/cloudflow-* /etc/cloudflow
```

`restorecon` is what actually applies the `.fc` labels to the already-installed
binaries and configs; without it the domain transition won't fire.

## Non-standard backend ports

The connect rules use `http_port_t`, which on RHEL 9 already covers 443, 8443,
and 9000 — so a ClickHouse HTTPS endpoint on :8443 (the shipped example) works
out of the box. Backends on other ports need a one-time label so the domain may
reach them:

```sh
# Splunk HEC on :8088
sudo semanage port -a -t http_port_t -p tcp 8088
# ClickHouse native HTTP on :8123
sudo semanage port -a -t http_port_t -p tcp 8123
```

Redis on the standard 6379 needs nothing (`redis_port_t`); a non-standard Redis
port would similarly need `semanage port -a -t redis_port_t -p tcp <port>`.

## Rollout: permissive first

These modules are written against the RHEL 9 `selinux-policy` interfaces and
target least privilege, but any new policy should be proven against the real
environment before it is enforced — a site's TLS trust store, name resolution,
or Redis topology can surface an access the module doesn't yet grant. Roll out
per host:

1. Install the modules, then put just these domains into permissive so a
   missing rule logs instead of blocking:

   ```sh
   sudo semanage permissive -a cloudflow_source_dhcp_t
   # ...repeat for each domain...
   ```

2. Run the services under real traffic for a representative window, then look
   for denials scoped to the CloudFlow domains:

   ```sh
   sudo ausearch -m avc -ts recent | grep cloudflow_
   ```

3. If any appear, turn them into a local addendum rather than loosening the
   shipped modules, and please open an issue so the base policy can be fixed:

   ```sh
   sudo ausearch -m avc -ts recent | grep cloudflow_ | audit2allow -M cloudflow_local
   sudo semodule -i cloudflow_local.pp
   ```

4. When a clean window produces no denials, drop permissive to enforce:

   ```sh
   sudo semanage permissive -d cloudflow_source_dhcp_t   # ...per domain...
   ```

## Verify

```sh
ps -eZ | grep cloudflow-                    # each process in its cloudflow_*_t domain
sesearch -A -s cloudflow_sink_splunk_t -c tcp_socket   # inspect what a domain may do
matchpathcon /usr/local/bin/cloudflow-source-dhcp /etc/cloudflow/dhcp-source.yaml
```

A process still showing `unconfined_service_t` (rather than a `cloudflow_*_t`
domain) means the entrypoint label didn't apply — re-run `restorecon` on the
binary and restart the unit.
