#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

error() { echo "ERROR: $*" >&2; }

if [[ "$(uname -s)" != "Linux" ]]; then
  error "This skeleton targets Linux hosts. Detected $(uname -s)."
  exit 1
fi

for bin in python3 ansible-playbook; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    error "Required binary missing: $bin"
    exit 1
  fi
done

INVENTORY="${ROOT_DIR}/inventory/hosts.yml"
VARS_FILE="${ROOT_DIR}/group_vars/all/main.yml"

if [[ ! -f "${INVENTORY}" ]]; then
  error "Missing inventory/hosts.yml. Run scripts/prepare.sh first."
  exit 1
fi

if [[ ! -f "${VARS_FILE}" ]]; then
  error "Missing group_vars/all/main.yml. Run scripts/prepare.sh first."
  exit 1
fi

python3 - <<'PY'
import ipaddress, sys, yaml, pathlib
vars_path = pathlib.Path(sys.argv[1])
with vars_path.open('r', encoding='utf-8') as fh:
    data = yaml.safe_load(fh) or {}

required = [
    'infra_domain', 'infra_realm', 'infra_core_hostname', 'infra_core_ip',
    'infra_dns_forwarders', 'infra_dhcp_subnet', 'infra_dhcp_range_start',
    'infra_dhcp_range_end', 'infra_dhcp_gateway', 'infra_tsig_secret',
    'chrony_ntp_servers', 'chrony_allow_networks',
    'cloudflared_proxy_dns_listen_port',
    'step_ca_root_password', 'step_ca_intermediate_password', 'step_ca_provisioner_password'
]

missing = [key for key in required if key not in data or data.get(key) in (None, '', [])]
if missing:
    print(f"Missing required variables in {vars_path}: {', '.join(missing)}")
    sys.exit(1)

def validate_ip(value, label):
    try:
        ipaddress.ip_address(value)
    except Exception as exc:
        print(f"Invalid {label}: {value} ({exc})")
        sys.exit(1)

validate_ip(data['infra_core_ip'], 'infra_core_ip')
validate_ip(data['infra_dhcp_range_start'], 'infra_dhcp_range_start')
validate_ip(data['infra_dhcp_range_end'], 'infra_dhcp_range_end')
validate_ip(data['infra_dhcp_gateway'], 'infra_dhcp_gateway')
for fwd in data.get('infra_dns_forwarders', []):
    validate_ip(str(fwd), 'infra_dns_forwarders')

try:
    ipaddress.ip_network(data['infra_dhcp_subnet'], strict=False)
except Exception as exc:
    print(f"Invalid infra_dhcp_subnet: {exc}")
    sys.exit(1)

if not data.get('chrony_ntp_servers'):
    print(f"chrony_ntp_servers must contain at least one entry in {vars_path}")
    sys.exit(1)

for net in data.get('chrony_allow_networks', []):
    try:
        ipaddress.ip_network(str(net), strict=False)
    except Exception as exc:
        print(f"Invalid chrony_allow_networks entry {net}: {exc}")
        sys.exit(1)

try:
    port = int(data.get('cloudflared_proxy_dns_listen_port', 0))
    if port <= 0 or port > 65535:
        raise ValueError("outside valid port range")
except Exception as exc:
    print(f"Invalid cloudflared_proxy_dns_listen_port: {exc}")
    sys.exit(1)
PY "${VARS_FILE}"

echo "Validation passed."
