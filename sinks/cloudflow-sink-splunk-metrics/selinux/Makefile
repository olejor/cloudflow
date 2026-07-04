# Build the cloudflow-sink-splunk-metrics SELinux policy module.
#
# Requires the policy devel tooling (RHEL9: `dnf install selinux-policy-devel`).
# `make` produces cloudflow_sink_splunk_metrics.pp; install it with:
#
#     sudo semodule -i cloudflow_sink_splunk_metrics.pp
#     sudo restorecon -Rv /usr/local/bin/cloudflow-sink-splunk-metrics /etc/cloudflow
#
# A non-standard HEC port needs a one-time label, e.g. for :8088
#     sudo semanage port -a -t http_port_t -p tcp 8088
#
# See ../../../docs/selinux.md for the full build / install / rollout guide.

include /usr/share/selinux/devel/Makefile
