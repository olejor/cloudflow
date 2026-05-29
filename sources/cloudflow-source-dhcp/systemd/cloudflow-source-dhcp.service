[Unit]
Description=CloudFlow DHCP source
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflow-source-dhcp --config /etc/cloudflow/dhcp-source.yaml
Restart=always
RestartSec=5
User=cloudflow
Group=cloudflow
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
