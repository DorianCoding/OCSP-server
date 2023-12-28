#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "You need to be root to execute this script."
  exit
fi
if [ ! -f config.toml ]; then
    echo "Put the config.toml file in the main directory"
fi
echo "Creating pycert user and group"
adduser --system pycert
if [ $? -ne 0 ]
  then echo "Error while creating the user, exiting"
  exit
fi
echo "Creating configuration file"
mkdir -p /var/ocsp/cache
if [ $? -ne 0 ]
  then echo "Error adding var/ocsp/ folder, exiting"
  exit
fi
echo "Creating binaries"
cp binaries/linux-x86_64_ocsp_server /var/ocsp/ocsp_server && cp config.toml /var/ocsp/config.toml
if [ $? -ne 0 ]
  then echo "Error copying files, exiting"
  exit
fi
chmod 640 config.toml && chmod 750 ocsp_server && chown root:pycert /var/ocsp/ && chmod 750 /var/ocsp/
if [ $? -ne 0 ]
  then echo "Error setting files, exiting"
  exit
fi
cat << EOF > /etc/systemd/system/ocspserver.service
# /etc/systemd/system/ocspserver.service
[Unit]
Description=OCSP Server
Requires=network.target
After=network.target
StartLimitIntervalSec=3m
StartLimitBurst=10
[Service]
Type=simple
RemainAfterExit=no
ExecStart=/var/ocsp/ocspserver
TimeoutStopSec=30
WorkingDirectory=/var/ocsp/
RestartSec=2
Restart=on-failure
OOMPolicy=continue
User=pycert
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ReadWritePaths=/var/ocsp/cache/
PrivateDevices=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
[Install]
WantedBy=multi-user.target
EOF
if [ $? -ne 0 ]
  then echo "Error setting services, exiting."
  exit
fi
systemctl daemon-reload && systemctl ocspserver enable && sudo service ocspserver start
if [ $? -ne 0 ]
  then echo "Error start services, exiting."
  exit
fi
echo "Success, good bye!"
