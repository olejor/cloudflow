# Build the cloudflow-sink-clickhouse SELinux policy module.
#
# Requires the policy devel tooling (RHEL9: `dnf install selinux-policy-devel`).
# `make` produces cloudflow_sink_clickhouse.pp; install it with:
#
#     sudo semodule -i cloudflow_sink_clickhouse.pp
#     sudo restorecon -Rv /usr/local/bin/cloudflow-sink-clickhouse /etc/cloudflow
#
# A non-standard native-HTTP port needs a one-time label, e.g. for :8123
#     sudo semanage port -a -t http_port_t -p tcp 8123
#
# See ../../../docs/selinux.md for the full build / install / rollout guide.

include /usr/share/selinux/devel/Makefile
