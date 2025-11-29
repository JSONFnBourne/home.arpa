# home.arpa core skeleton

Minimal, hardware-agnostic HOME.ARPA core stack: Chrony time sync, Cloudflare DoH forwarder, Step-CA-backed TLS, authoritative DNS + DHCP, LDAP + Kerberos identity, SSSD client enrollment example, reverse proxy for Prometheus/Grafana, and the monitoring stack itself.

## Supported targets
- Control node: any machine with Ansible installed.
- Managed hosts: Ubuntu Server LTS or Raspberry Pi OS with SSH + sudo access.

## Quick start
1. Clone this repository next to your own projects.
2. Run `./scripts/prepare.sh` (interactive) or `./scripts/prepare.sh --config myconfig.yml`.
3. Run `./scripts/validate.sh` to confirm prerequisites and variable sanity.
4. Deploy: `./scripts/deploy.sh` (optional: `LIMIT=core` or `TAGS=network,monitoring` environment variables).

## What gets deployed
- **Platform**: Chrony NTP, Cloudflare `cloudflared` DNS-over-HTTPS forwarder, and Smallstep `step-ca` issuing host TLS for services.
- **Core network**: BIND authoritative DNS for your domain, Kea DHCPv4 for a single subnet, TSIG-enabled DDNS between them.
- **Identity**: OpenLDAP directory with base OUs; MIT Kerberos realm bound to your domain.
- **Client integration**: SSSD role + example playbook for Linux clients.
- **Reverse proxy**: NGINX fronting `/prometheus` and `/grafana` (uses the Step-CA host cert by default; swap to ACME if desired).
- **Monitoring**: Prometheus + blackbox exporter + Grafana with a minimal “Internet Probes” dashboard. Targets default to the required ICMP set plus existing AWS HTTPS endpoints from the source project.

## Variables and overrides
`scripts/prepare.sh` writes `inventory/hosts.yml` and `group_vars/all/main.yml` (a placeholder example lives at `group_vars/all/main.example.yml`). Key knobs:
- `infra_domain` (default `home.arpa`) and `infra_realm` (uppercase domain).
- `infra_core_hostname`, `infra_core_ip`, DHCP CIDR/range/gateway.
- `chrony_ntp_servers`, `chrony_allow_networks`, `infra_dns_forwarders` (used by BIND), `bind_forwarders` (defaults to `cloudflared` on localhost), `infra_tsig_secret` (base64 placeholder).
- `cloudflared_proxy_dns_*` (listen port, upstream DoH endpoints, bootstrap IPs), `step_ca_*` (passwords, SANs, paths).
- `monitoring_enable`, `reverse_proxy_enable_https`.
- Password placeholders: `ldap_admin_password`, `kerberos_master_password`, `kerberos_admin_password`, `monitoring_grafana_admin_password`, plus the three Step-CA passwords.
Edit `group_vars/all/main.yml` to override defaults or set extra role vars.

### Non-interactive bootstrap
Provide a YAML file matching `group_vars/all/main.yml` keys, e.g.:
```yaml
infra_domain: example.lan
infra_core_hostname: core
infra_core_ip: 10.10.0.5
infra_dhcp_subnet: 10.10.0.0/24
infra_dhcp_range_start: 10.10.0.100
infra_dhcp_range_end: 10.10.0.150
infra_dhcp_gateway: 10.10.0.1
infra_dns_forwarders:
  - 1.1.1.1
  - 8.8.8.8
monitoring_enable: true
reverse_proxy_enable_https: false
```
Run `./scripts/prepare.sh --config myconfig.yml` (requires local `PyYAML`).
Chrony, cloudflared, and Step-CA fields are auto-populated; override them in your config if you need custom NTP, DoH, or PKI settings.

## Playbooks
- `playbooks/site.yml` orchestrates: platform services → core network → identity → reverse proxy → monitoring.
- `playbooks/core_services.yml`: Chrony NTP, Step-CA, and cloudflared DoH forwarder (tags: `time`, `ca`, `dns`).
- `playbooks/core_network.yml`: BIND + Kea (tags: `dns`, `dhcp`, `network`).
- `playbooks/core_identity.yml`: OpenLDAP + Kerberos (tag: `identity`).
- `playbooks/reverse_proxy.yml`: NGINX front-end (tag: `proxy`).
- `playbooks/monitoring.yml`: Prometheus + Grafana (tag: `monitoring`, gated by `monitoring_enable`).
- `playbooks/client_enroll.yml`: Example SSSD client enrollment (hosts group `clients`, tag: `client`).

## Extending safely
- Add more monitoring targets via `monitoring_targets_icmp` / `monitoring_targets_https`.
- Bring in extra exporters or services by creating new roles under `roles/` and importing them in `playbooks/site.yml`.
- Keep secrets out of git: replace all `CHANGEME` values and store real secrets in Ansible Vault if desired.

## Security notes
- No real passwords ship with this repo. **You must change all placeholder secrets** before any production use.
- Step-CA issues the host certificate by default; change the Step-CA passwords and rotate certs or swap to ACME as needed.
- Inventory and generated vars are gitignored by default (`inventory/hosts.yml`, `group_vars/all/main.yml`).
