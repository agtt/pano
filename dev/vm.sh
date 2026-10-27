#!/bin/bash
# End-to-end test in a real AlmaLinux 9 VM (OrbStack, macOS):
#   dev/vm.sh            create/provision the VM, build, install pano, create admin
#   VM=name dev/vm.sh    use another machine name
# Then open http://<vm-ip>:7800 (the VM's panel listens on its own IP).
set -euo pipefail
VM=${VM:-pano-test}
cd "$(dirname "$0")/.."

orb list | grep -q "^$VM " || orb create --memory 4G --cpus 4 alma:9 "$VM"
ARCH=$(orb -m "$VM" uname -m)
if [ "$ARCH" = "aarch64" ]; then bun run build:arm; BIN=dist/pano-arm64; else bun run build; BIN=dist/pano; fi

orb -m "$VM" -u root bash -s < dev/vm-provision.sh
orb -m "$VM" -u root install -m 0755 "$PWD/$BIN" /tmp/pano
orb -m "$VM" -u root /tmp/pano install
IP=$(orb -m "$VM" hostname -I | awk '{print $1}')
orb -m "$VM" -u root sed -i "s/^PANO_WEB_HOST=.*/PANO_WEB_HOST=$IP/" /etc/pano/pano.env
orb -m "$VM" -u root systemctl restart pano-web
orb -m "$VM" -u root /opt/pano/bin/pano admin admin "${PANO_ADMIN_PASSWORD:-pano-vm-password}"
echo "panel: http://$IP:7800  (admin / ${PANO_ADMIN_PASSWORD:-pano-vm-password}; 2FA secret above)"
