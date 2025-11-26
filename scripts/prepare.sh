#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY_PATH="${ROOT_DIR}/inventory/hosts.yml"
GROUP_VARS_PATH="${ROOT_DIR}/group_vars/all/main.yml"

CONFIG_FILE=""

usage() {
  cat <<EOF
Usage: $(basename "$0") [--config path/to/config.yml]

Without --config the script runs interactively and writes:
  - inventory/hosts.yml
  - group_vars/all/main.yml
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_FILE="$2"; shift 2;;
    -h|--help)
      usage;;
    *)
      echo "Unknown argument: $1" >&2
      usage;;
  esac
done

prompt() {
  local var_name="$1" prompt_text="$2" default="$3"
  local value
  read -rp "${prompt_text} [${default}]: " value
  if [[ -z "${value:-}" ]]; then
    value="$default"
  fi
  printf -v "$var_name" '%s' "$value"
}

calc_reverse_zone() {
  python3 - "$1" <<'PY'
import ipaddress, sys
cidr = sys.argv[1]
net = ipaddress.ip_network(cidr, strict=False)
octets = str(net.network_address).split('.')
octet_count = max(1, (net.prefixlen + 7) // 8)
reverse_parts = list(reversed(octets[:octet_count]))
reverse_zone = '.'.join(reverse_parts) + '.in-addr.arpa'
reverse_file = 'db.' + '.'.join(octets[:octet_count])
print(reverse_zone)
print(reverse_file)
PY
}

load_config() {
  python3 - "$CONFIG_FILE" <<'PY'
import sys, json
try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required to parse --config files. Install with pip install pyyaml\\n")
    sys.exit(1)
path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as fh:
    data = yaml.safe_load(fh) or {}
print(json.dumps(data))
PY
}

declare infra_domain infra_realm infra_core_hostname infra_core_ip infra_dhcp_subnet infra_dhcp_range_start infra_dhcp_range_end infra_dhcp_gateway dns_forwarders monitoring_enable reverse_proxy_enable_https grafana_password tsig_secret ansible_user ansible_port

if [[ -n "${CONFIG_FILE}" ]]; then
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "Config file not found: ${CONFIG_FILE}" >&2
    exit 1
  fi
  mapfile -t cfg_lines < <(load_config)
  cfg_json="${cfg_lines[*]}"
  infra_domain=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('infra_domain','home.arpa'))\nPY <<<"${cfg_json}")
  infra_realm=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\ndomain=cfg.get('infra_domain','home.arpa')\nprint(cfg.get('infra_realm', domain.upper()))\nPY <<<"${cfg_json}")
  infra_core_hostname=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('infra_core_hostname','core'))\nPY <<<"${cfg_json}")
  infra_core_ip=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('infra_core_ip','192.168.10.2'))\nPY <<<"${cfg_json}")
  infra_dhcp_subnet=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('infra_dhcp_subnet','192.168.10.0/24'))\nPY <<<"${cfg_json}")
  infra_dhcp_range_start=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('infra_dhcp_range_start','192.168.10.100'))\nPY <<<"${cfg_json}")
  infra_dhcp_range_end=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('infra_dhcp_range_end','192.168.10.200'))\nPY <<<"${cfg_json}")
  infra_dhcp_gateway=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('infra_dhcp_gateway','192.168.10.1'))\nPY <<<"${cfg_json}")
  dns_forwarders=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(','.join(cfg.get('infra_dns_forwarders',['1.1.1.1','8.8.8.8'])))\nPY <<<"${cfg_json}")
  monitoring_enable=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(str(cfg.get('monitoring_enable', True)).lower())\nPY <<<"${cfg_json}")
  reverse_proxy_enable_https=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(str(cfg.get('reverse_proxy_enable_https', False)).lower())\nPY <<<"${cfg_json}")
  grafana_password=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('monitoring_grafana_admin_password','CHANGEME_GRAFANA_ADMIN'))\nPY <<<"${cfg_json}")
  tsig_secret=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('infra_tsig_secret','CHANGEME_TSIG_BASE64'))\nPY <<<"${cfg_json}")
  ansible_user=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('ansible_user','ubuntu'))\nPY <<<"${cfg_json}")
  ansible_port=$(python3 - <<'PY'\nimport json,sys\ncfg=json.loads(sys.stdin.read())\nprint(cfg.get('ansible_port',22))\nPY <<<"${cfg_json}")
else
  prompt infra_domain "Primary domain" "home.arpa"
  default_realm="$(echo "${infra_domain}" | tr '[:lower:]' '[:upper:]')"
  prompt infra_realm "Kerberos realm" "${default_realm}"
  prompt infra_core_hostname "Core server hostname" "core"
  prompt infra_core_ip "Core server IP" "192.168.10.2"
  prompt infra_dhcp_subnet "DHCP subnet CIDR" "192.168.10.0/24"
  prompt infra_dhcp_range_start "DHCP range start" "192.168.10.100"
  prompt infra_dhcp_range_end "DHCP range end" "192.168.10.200"
  prompt infra_dhcp_gateway "Default gateway" "192.168.10.1"
  prompt dns_forwarders "DNS forwarders (comma separated)" "1.1.1.1,8.8.8.8"
  prompt monitoring_enable "Enable Prometheus + Grafana? (true/false)" "true"
  prompt reverse_proxy_enable_https "Enable HTTPS on reverse proxy? (true/false)" "false"
  prompt grafana_password "Grafana admin password" "CHANGEME_GRAFANA_ADMIN"
  prompt tsig_secret "TSIG secret (base64)" "CHANGEME_TSIG_BASE64"
  prompt ansible_user "Ansible SSH user" "ubuntu"
  prompt ansible_port "SSH port" "22"
fi

infra_core_fqdn="${infra_core_hostname}.${infra_domain}"
mapfile -t reverse_info < <(calc_reverse_zone "${infra_dhcp_subnet}")
infra_reverse_zone="${reverse_info[0]}"
infra_reverse_zone_file="${reverse_info[1]}"

IFS=',' read -r -a forwarders_array <<<"${dns_forwarders}"

mkdir -p "${ROOT_DIR}/inventory" "${ROOT_DIR}/group_vars/all"

cat > "${INVENTORY_PATH}" <<EOF
all:
  hosts:
    core:
      ansible_host: ${infra_core_ip}
      ansible_user: ${ansible_user}
      ansible_port: ${ansible_port}
  vars:
    ansible_become: true
EOF

cat > "${GROUP_VARS_PATH}" <<EOF
infra_domain: ${infra_domain}
infra_realm: ${infra_realm}
infra_core_hostname: ${infra_core_hostname}
infra_core_ip: ${infra_core_ip}
infra_core_fqdn: ${infra_core_fqdn}
infra_dns_forwarders:
$(for f in "${forwarders_array[@]}"; do echo "  - ${f}"; done)

infra_dhcp_subnet: ${infra_dhcp_subnet}
infra_dhcp_range_start: ${infra_dhcp_range_start}
infra_dhcp_range_end: ${infra_dhcp_range_end}
infra_dhcp_gateway: ${infra_dhcp_gateway}
infra_dhcp_name_server: ${infra_core_ip}
infra_reverse_zone: ${infra_reverse_zone}
infra_reverse_zone_file: ${infra_reverse_zone_file}
infra_tsig_secret: ${tsig_secret}

ldap_admin_password: CHANGEME_LDAP_ADMIN
kerberos_master_password: CHANGEME_KRB5_MASTER
kerberos_admin_password: CHANGEME_KRB5_ADMIN

monitoring_enable: ${monitoring_enable}
monitoring_blackbox_http_scheme: https
monitoring_grafana_admin_user: admin
monitoring_grafana_admin_password: ${grafana_password}

reverse_proxy_enable_https: ${reverse_proxy_enable_https}
reverse_proxy_acme_email: user@example.com
reverse_proxy_upstreams:
  - name: grafana
    path: /grafana/
    upstream: http://127.0.0.1:3000
    websocket: true
    strip_path: false
  - name: prometheus
    path: /prometheus/
    upstream: http://127.0.0.1:9090
    websocket: false
    strip_path: false
EOF

echo "Generated ${INVENTORY_PATH} and ${GROUP_VARS_PATH}"
