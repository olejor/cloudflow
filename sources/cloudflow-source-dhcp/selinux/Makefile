# Build the cloudflow-source-dhcp SELinux policy module.
#
# Requires the policy devel tooling (RHEL9: `dnf install selinux-policy-devel`).
# `make` produces cloudflow_source_dhcp.pp; install it with:
#
#     sudo semodule -i cloudflow_source_dhcp.pp
#     sudo restorecon -Rv /usr/local/bin/cloudflow-source-dhcp /etc/cloudflow
#
# See ../../../docs/selinux.md for the full build / install / rollout guide.

include /usr/share/selinux/devel/Makefile
