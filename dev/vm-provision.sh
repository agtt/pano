#!/bin/bash
# Runs as root inside the test VM: makes it look like a small CyberPanel box
# (MariaDB, OpenLiteSpeed on :80 with one PHP-less legacy site and one proxy
# site in front of a systemd service on :3000).
set -euo pipefail

dnf -y -q install git tar xz unzip curl mariadb-server openssh-clients procps-ng iproute libatomic libxcrypt-compat python3 >/dev/null
systemctl enable --now mariadb >/dev/null

if [ ! -x /usr/local/lsws/bin/lswsctrl ]; then
  curl -fsS -o /etc/pki/rpm-gpg/RPM-GPG-KEY-litespeed https://rpms.litespeedtech.com/centos/RPM-GPG-KEY-litespeed2025
  cat > /etc/yum.repos.d/litespeed.repo <<'EOF'
[litespeed]
name=LiteSpeed Tech
baseurl=http://rpms.litespeedtech.com/centos/$releasever/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-litespeed
EOF
  # The bundled lsphp needs a gd build the stock repos lack on arm64; the test
  # sites are plain HTML, so OpenLiteSpeed is installed without its PHP deps.
  dnf -y -q install openlitespeed >/dev/null 2>&1 || {
    (cd /tmp && dnf -q download openlitespeed && rpm -i --nodeps /tmp/openlitespeed-*.rpm)
  }
fi

CONF=/usr/local/lsws/conf/httpd_config.conf
if ! grep -q "virtualhost legacy.test" "$CONF"; then
  mkdir -p /home/legacy.test/public_html /home/proxy.test/html /usr/local/lsws/conf/vhosts/legacy.test /usr/local/lsws/conf/vhosts/proxy.test
  echo "legacy site served by OpenLiteSpeed" > /home/legacy.test/public_html/index.html
  cat > /usr/local/lsws/conf/vhosts/legacy.test/vhost.conf <<'EOF'
docRoot                   $VH_ROOT/public_html
vhDomain                  $VH_NAME
enableGzip                1
index  {
  useServer               0
  indexFiles              index.html
}
EOF
  cat > /usr/local/lsws/conf/vhosts/proxy.test/vhost.conf <<'EOF'
docRoot                   $VH_ROOT/html
vhDomain                  proxy.test
extprocessor demo {
  type                    proxy
  address                 127.0.0.1:3000
  maxConns                100
}
context / {
  type                    proxy
  handler                 demo
  addDefaultCharset       off
}
EOF
  chown -R lsadm:nobody /usr/local/lsws/conf/vhosts
  # Listener on :80 like CyberPanel, mapping both sites.
  sed -i 's/^\(\s*address\s*\)\*:8088/\1*:80/' "$CONF"
  sed -i '/^listener Default/,/^}/ s/^\(\s*map\s*Example\s*\).*/\1*\n  map                     legacy.test legacy.test\n  map                     proxy.test proxy.test/' "$CONF"
  cat >> "$CONF" <<'EOF'

virtualhost legacy.test {
  vhRoot                  /home/legacy.test
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhost.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
}

virtualhost proxy.test {
  vhRoot                  /home/proxy.test
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhost.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
}
EOF
fi

# A pre-existing app behind the proxy site, run by its own systemd unit.
if [ ! -f /etc/systemd/system/demo-legacy.service ]; then
  mkdir -p /opt/demo && cat > /opt/demo/server.py <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"legacy demo app\n")
HTTPServer(("127.0.0.1", 3000), H).serve_forever()
EOF
  cat > /etc/systemd/system/demo-legacy.service <<'EOF'
[Unit]
Description=demo legacy app
[Service]
ExecStart=/usr/bin/python3 /opt/demo/server.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload && systemctl enable --now demo-legacy >/dev/null
fi

/usr/local/lsws/bin/lswsctrl restart >/dev/null
sleep 2
echo "legacy: $(curl -s -H 'Host: legacy.test' http://127.0.0.1/)"
echo "proxy:  $(curl -s -H 'Host: proxy.test' http://127.0.0.1/)"
