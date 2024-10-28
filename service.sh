#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "You need to be root to execute this script."
  exit
fi
if [ ! -f config.toml ]; then
    echo "Put the config.toml file in the main directory"
    exit
fi
if [ ! -f target/release/ocsp-server ]; then
    echo "Please execute cargo build --release before."
    exit
fi
echo "Creating pycert user and group"
adduser --system pycert --group
if [ $? -ne 0 ]
  then echo "Error while creating the user, exiting"
  exit
fi
echo -n "Cancel the script by Ctrl+C now if you did not edit config.toml and change it now, else the script won't work"
read -t 10
echo "Creating cache directory"
mkdir -p /var/ocsp/cache
if [ $? -ne 0 ]
  then echo "Error adding var/ocsp/cache folder, exiting"
  exit
fi
echo "Creating binaries"
cp target/release/ocsp-server /var/ocsp/ocsp_server && cp config.toml /var/ocsp/
if [ $? -ne 0 ]
  then echo "Error copying files, exiting. Please execute cargo build --release before."
  exit
fi
cd /var/ocsp
if [ $? -ne 0 ]
  then echo "Error moving to /var/ocsp"
  exit
fi
chmod 640 config.toml && cp chmod 750 ocsp_server && chown root:pycert /var/ocsp/ && chmod 750 /var/ocsp/
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
AmbientCapabilities=CAP_NET_BIND_SERVICE
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
systemctl daemon-reload && systemctl enable ocspserver && systemctl start ocspserver
if [ $? -ne 0 ]
  then echo "Error start services, exiting."
  exit
fi
echo "Success, good bye!"
