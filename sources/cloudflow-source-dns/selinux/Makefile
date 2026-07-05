# Build the cloudflow-source-dns SELinux policy module.
#
# Requires the policy devel tooling (RHEL9: `dnf install selinux-policy-devel`).
# `make` produces cloudflow_source_dns.pp; install it with:
#
#     sudo semodule -i cloudflow_source_dns.pp
#     sudo restorecon -Rv /usr/local/bin/cloudflow-source-dns /etc/cloudflow
#
# See ../../../docs/selinux.md for the full build / install / rollout guide.

include /usr/share/selinux/devel/Makefile
