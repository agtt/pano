#!/bin/bash
# What the test VM holds right now: apps, sites, backup jobs and stores.
set -euo pipefail
VM=${VM:-pano-test}
rpc() { orb -m "$VM" -u root /opt/pano/bin/pano rpc "$1" "${2:-"{}"}"; }
rpc apps.list | jq -c '[.[] | {name, kind, status}]'
rpc sites.list | jq -c '[.[] | {name, kind}]'
rpc backup.jobs | jq -c '[.[] | {id, name, kind, target, schedule, keep}]'
rpc backup.settings | jq -c '{engine, kit, a: .a.bucket, b: .b.bucket, ap: .a.protect, bp: .b.protect}'
