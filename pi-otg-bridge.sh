#!/usr/bin/env bash
# ============================================================
# Raspberry Pi ↔ iPad USB Ethernet Gadget Workstation Setup
# Version 3.7 — hardened, portable, idempotent, with rollback
#
# v3.7: Merges best of v3.5 + v3.6
#   From v3.6 (kept):
#     ✓ managed_write_file() helper (unified backup/track + atomic write)
#     ✓ Dynamic nft filename: ipad-${USB_IFACE}.nft (not hardcoded usb0)
#     ✓ Dynamic Samba marker: IPAD-${USB_IFACE}-V3 + legacy usb0 cleanup
#     ✓ _chk_iface_has_ip exact match via ip -o -4 addr
#     ✓ Uninstall cleans both old (usb0) and new (${USB_IFACE}) filenames
#   From v3.5 (restored):
#     ✓ service_record_prev_state de-dup (declare -A _SVC_RECORDED)
#     ✓ --purge mode + apt_purge_with_confirm() with separate confirmation
#     ✓ validate_usb_subnet_sanity() + ipv4_to_int() with ERROR sentinel
#     ✓ eval-free health check (_chk_* functions called by reference)
#     ✓ --purge / --remove-boot flag combination validation in parse_args
#     ✓ Robust dnsmasq UDP:67 check (not IP-specific)
#     ✓ Tolerant nftables regex (version-agnostic spacing)
#
# ── Section Index ──────────────────────────────────
#   §0  Constants, globals, output helpers
#   §1  Trap / rollback / lockfile
#   §2  Defaults (env overrides)
#   §3  Generic helpers (backup, managed_write, apt, cidr, validation)
#   §4  Detection helpers (boot, upstream, Pi model)
#   §5  Boot config (dwc2 + g_ether)
#   §6  Static IP (NetworkManager / systemd-networkd)
#   §7  dnsmasq DHCP
#   §8  IPv4 forwarding
#   §9  nftables NAT + forward
#   §10 tmux
#   §11 Samba (hardened)
#   §12 --check health validation (eval-free)
#   §13 --uninstall / --purge
#   §14 CLI argument parsing + validation
#   §15 main()
# ───────────────────────────────────────────────────
#
# Usage:
#   sudo ./rpi-ipad-otg-setup.v3.7.sh
#   sudo ./rpi-ipad-otg-setup.v3.7.sh --dry-run
#   sudo ./rpi-ipad-otg-setup.v3.7.sh --check
#   sudo ./rpi-ipad-otg-setup.v3.7.sh --uninstall [--remove-boot] [--purge]
#   sudo ./rpi-ipad-otg-setup.v3.7.sh --version
#
# Env overrides:
#   USB_IFACE=usb0 USB_IP=10.55.0.1 USB_PREFIX=29 USB_SUBNET_CIDR=10.55.0.0/29
#   DHCP_START=10.55.0.2 DHCP_END=10.55.0.6 DHCP_LEASE=12h
#   DNS1=1.1.1.1 DNS2=8.8.8.8 UPSTREAM_IFACE=auto
#   INSTALL_TMUX=1 INSTALL_SAMBA=1 SAMBA_USER=ipadshare
#   SAMBA_SHARE_DIR=/srv/ipad-share SAMBA_PASS=... ENABLE_GUEST_SAMBA=0
#   SKIP_BOOT=0 SKIP_NETWORK=0 SKIP_NAT=0
# ============================================================

set -euo pipefail
shopt -s nullglob

# ═══════════════════════════════════════════════════
# §0  Constants, globals, output helpers
# ═══════════════════════════════════════════════════
readonly SCRIPT_VERSION="3.7.0"
readonly LOCKFILE="/var/run/rpi-ipad-otg-setup.lock"
readonly LOG_FILE="/var/log/rpi-ipad-otg-setup.log"

BOOT_DIR=""
CONFIG_TXT=""
CMDLINE_TXT=""
UPSTREAM=""
DRY_RUN=0
CHECK_MODE=0
UNINSTALL_MODE=0
UNINSTALL_REMOVE_BOOT=0
PURGE_MODE=0
RUN_START_EPOCH=""

declare -a BACKUP_REGISTRY=()
declare -a CREATED_FILES=()
declare -a CREATED_USERS=()
declare -a CREATED_NM_CONNS=()
declare -a SERVICE_PREV_STATE=()
declare -a CLEANUP_HOOKS=()

# Service de-dup tracking (from v3.5)
declare -A _SVC_RECORDED=()

readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_RED='\033[0;31m'
readonly C_CYAN='\033[0;36m'
readonly C_DIM='\033[2m'
readonly C_BOLD='\033[1m'
readonly C_NC='\033[0m'

_ts()   { date +"%Y-%m-%d %H:%M:%S"; }
_log()  { echo -e "$(_ts) $*" >> "$LOG_FILE" 2>/dev/null || true; }

info()  { echo -e "${C_GREEN}[✓]${C_NC} $*"; _log "[INFO] $*"; }
warn()  { echo -e "${C_YELLOW}[!]${C_NC} $*"; _log "[WARN] $*"; }
fail()  { echo -e "${C_RED}[✗]${C_NC} $*"; _log "[FAIL] $*"; exit 1; }
step()  { echo -e "\n${C_CYAN}━━━${C_NC} $* ${C_CYAN}━━━${C_NC}"; _log "[STEP] $*"; }
dry()   { echo -e "${C_DIM}  [dry-run] $*${C_NC}"; }

# ═══════════════════════════════════════════════════
# §1  Trap / rollback / lockfile
# ═══════════════════════════════════════════════════
cleanup_lock() { rm -f "$LOCKFILE"; }

# Record a service's enabled state for rollback (de-duplicated)
service_record_prev_state() {
  local svc="$1"
  if [[ -n "${_SVC_RECORDED[$svc]:-}" ]]; then
    return 0
  fi
  _SVC_RECORDED["$svc"]=1
  local was=0
  if systemctl is-enabled --quiet "$svc" 2>/dev/null; then was=1; fi
  SERVICE_PREV_STATE+=("${svc}|${was}")
}

service_restore_prev_state() {
  local svc="$1" was="$2"
  if [[ "$was" == "1" ]]; then
    systemctl enable "$svc" >/dev/null 2>&1 || true
  else
    systemctl disable "$svc" >/dev/null 2>&1 || true
  fi
}

rollback() {
  local exit_code=$?

  for hook in "${CLEANUP_HOOKS[@]:-}"; do
    [[ -n "$hook" ]] && "$hook" 2>/dev/null || true
  done

  if [[ $exit_code -ne 0 ]]; then
    echo ""
    warn "⚠ Script failed (exit $exit_code). Rolling back..."

    # 1) Restore file backups
    if [[ ${#BACKUP_REGISTRY[@]} -gt 0 ]]; then
      warn "Restoring ${#BACKUP_REGISTRY[@]} backup(s)..."
      for entry in "${BACKUP_REGISTRY[@]}"; do
        local orig="${entry%%|*}" bak="${entry##*|}"
        if [[ -f "$bak" ]]; then
          cp -a "$bak" "$orig" || true
          warn "  Restored: $orig ← $bak"
        fi
      done
    fi

    # 2) Remove files created by this run
    if [[ ${#CREATED_FILES[@]} -gt 0 ]]; then
      warn "Removing ${#CREATED_FILES[@]} file(s) created by this run..."
      for f in "${CREATED_FILES[@]}"; do
        rm -f "$f" 2>/dev/null || true
        warn "  Removed: $f"
      done
    fi

    # 3) Remove NM connections created by this run
    if [[ ${#CREATED_NM_CONNS[@]} -gt 0 ]] && command -v nmcli >/dev/null 2>&1; then
      warn "Removing ${#CREATED_NM_CONNS[@]} NM connection(s)..."
      for c in "${CREATED_NM_CONNS[@]}"; do
        nmcli connection delete "$c" >/dev/null 2>&1 || true
        warn "  Deleted NM: $c"
      done
    fi

    # 4) Restore service enabled states
    if [[ ${#SERVICE_PREV_STATE[@]} -gt 0 ]]; then
      warn "Restoring service enablement..."
      for e in "${SERVICE_PREV_STATE[@]}"; do
        local svc="${e%%|*}" was="${e##*|}"
        service_restore_prev_state "$svc" "$was"
        warn "  $svc → enabled=$was"
      done
    fi

    # 5) Remove users created by this run
    if [[ ${#CREATED_USERS[@]} -gt 0 ]]; then
      warn "Removing ${#CREATED_USERS[@]} user(s)..."
      for u in "${CREATED_USERS[@]}"; do
        userdel "$u" >/dev/null 2>&1 || true
        warn "  Deleted user: $u"
      done
    fi

    warn "Rollback complete. See $LOG_FILE for details."
  fi

  cleanup_lock
}

acquire_lock() {
  if [[ $DRY_RUN -eq 1 ]]; then
    return 0
  fi
  if [[ -f "$LOCKFILE" ]]; then
    local pid
    pid="$(cat "$LOCKFILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      fail "Another instance running (PID $pid). Remove $LOCKFILE if stale."
    else
      warn "Stale lockfile removed."
      rm -f "$LOCKFILE"
    fi
  fi
  echo $$ > "$LOCKFILE"
  CLEANUP_HOOKS+=("cleanup_lock")
}

trap rollback EXIT
trap 'exit 1' INT TERM

# ═══════════════════════════════════════════════════
# §2  Defaults (override via env)
# ═══════════════════════════════════════════════════
USB_IFACE="${USB_IFACE:-usb0}"
USB_IP="${USB_IP:-10.55.0.1}"
USB_PREFIX="${USB_PREFIX:-29}"
USB_SUBNET_CIDR="${USB_SUBNET_CIDR:-10.55.0.0/29}"
DHCP_START="${DHCP_START:-10.55.0.2}"
DHCP_END="${DHCP_END:-10.55.0.6}"
DHCP_LEASE="${DHCP_LEASE:-12h}"
DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-8.8.8.8}"
UPSTREAM_IFACE="${UPSTREAM_IFACE:-auto}"
INSTALL_TMUX="${INSTALL_TMUX:-1}"
INSTALL_SAMBA="${INSTALL_SAMBA:-1}"
SAMBA_USER="${SAMBA_USER:-ipadshare}"
SAMBA_SHARE_DIR="${SAMBA_SHARE_DIR:-/srv/ipad-share}"
SAMBA_PASS="${SAMBA_PASS:-}"
ENABLE_GUEST_SAMBA="${ENABLE_GUEST_SAMBA:-0}"
SKIP_BOOT="${SKIP_BOOT:-0}"
SKIP_NETWORK="${SKIP_NETWORK:-0}"
SKIP_NAT="${SKIP_NAT:-0}"

USB_NETMASK=""  # computed at runtime from USB_PREFIX

# ═══════════════════════════════════════════════════
# §3  Generic helpers
# ═══════════════════════════════════════════════════
have_cmd() { command -v "$1" >/dev/null 2>&1; }

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local bak="${f}.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a "$f" "$bak"
  BACKUP_REGISTRY+=("${f}|${bak}")
  info "Backup: $f → $bak"
}

track_created_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    CREATED_FILES+=("$f")
  fi
}

atomic_write() {
  local dest="$1"
  local tmp="${dest}.tmp.$$"
  cat > "$tmp"
  mv -f "$tmp" "$dest"
}

# Unified file management: backup if exists, else track as created, then atomic write.
# Reads content from stdin. In dry-run mode, drains stdin and returns.
# (from v3.6)
managed_write_file() {
  local dest="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    dry "Would write file: $dest"
    cat >/dev/null
    return 0
  fi
  if [[ -f "$dest" ]]; then
    backup_file "$dest"
  else
    track_created_file "$dest"
  fi
  atomic_write "$dest"
}

# ── CIDR / IP helpers ──

cidr_to_netmask() {
  local pfx="$1"
  (( pfx >= 0 && pfx <= 32 )) || fail "Invalid CIDR prefix: $pfx"
  local remaining=$pfx
  local mask="" octet bits
  for octet in 1 2 3 4; do
    bits=$(( remaining >= 8 ? 8 : remaining ))
    remaining=$(( remaining - bits ))
    local val=$(( bits == 0 ? 0 : (256 - (1 << (8 - bits))) ))
    mask+="${val}"
    [[ $octet -lt 4 ]] && mask+="."
  done
  echo "$mask"
}

# IPv4 dotted quad → unsigned integer.
# Returns "ERROR" sentinel on invalid input (safe under set -e). (from v3.5)
ipv4_to_int() {
  local ip="$1"
  local result
  result="$(echo "$ip" | awk -F. '
    NF != 4 { print "ERROR"; exit 0 }
    {
      for (i = 1; i <= 4; i++) {
        if ($i !~ /^[0-9]+$/) { print "ERROR"; exit 0 }
        if ($i + 0 < 0 || $i + 0 > 255) { print "ERROR"; exit 0 }
      }
      printf "%u\n", ($1 * 16777216) + ($2 * 65536) + ($3 * 256) + $4
    }')"
  if [[ "$result" == "ERROR" || -z "$result" ]]; then
    return 1
  fi
  echo "$result"
}

# CIDR "a.b.c.d/p" → "net_int|mask_int|pfx"
cidr_to_netmask_ints() {
  local cidr="$1"
  local ip="${cidr%/*}"
  local pfx="${cidr##*/}"
  (( pfx >= 0 && pfx <= 32 )) || return 1

  local ip_int mask_int net_int
  ip_int="$(ipv4_to_int "$ip")" || return 1

  if (( pfx == 0 )); then
    mask_int=0
  else
    mask_int=$(( (0xFFFFFFFF << (32 - pfx)) & 0xFFFFFFFF ))
  fi
  net_int=$(( ip_int & mask_int ))
  echo "${net_int}|${mask_int}|${pfx}"
}

# Validate USB_IP is inside USB_SUBNET_CIDR with matching prefix. (from v3.5)
# Intentionally runs in --dry-run too to catch config errors early.
validate_usb_subnet_sanity() {
  local ip="$USB_IP" pfx="$USB_PREFIX" subnet="$USB_SUBNET_CIDR"

  # 1) Prefix must match
  local subnet_pfx="${subnet##*/}"
  if [[ "$subnet_pfx" != "$pfx" ]]; then
    fail "USB_SUBNET_CIDR prefix (${subnet_pfx}) ≠ USB_PREFIX (${pfx}). Fix env overrides."
  fi

  # 2) IP must be within the declared subnet
  local ip_int
  ip_int="$(ipv4_to_int "$ip")" || fail "Invalid USB_IP: '$ip'"

  local triple
  triple="$(cidr_to_netmask_ints "$subnet")" || fail "Invalid USB_SUBNET_CIDR: '$subnet'"

  local subnet_net="${triple%%|*}"
  local rest="${triple#*|}"
  local mask_int="${rest%%|*}"

  local ip_net=$(( ip_int & mask_int ))
  if [[ "$ip_net" != "$subnet_net" ]]; then
    fail "USB_IP ${ip}/${pfx} is NOT inside USB_SUBNET_CIDR ${subnet}. Fix your env overrides."
  fi

  info "Sanity OK: ${ip}/${pfx} ∈ ${subnet}"
}

# ── Module list helpers ──

list_contains_mod() {
  local list="$1" mod="$2"
  echo "$list" | awk -F'[, \t]+' -v m="$mod" '
    { for (i=1; i<=NF; i++) if ($i == m) { found=1; exit } }
    END { exit !found }
  '
}

# ── apt helpers ──

_apt_updated=0
apt_ensure_updated() {
  if [[ $_apt_updated -eq 0 ]]; then
    export DEBIAN_FRONTEND=noninteractive
    info "Running apt-get update (once)..."
    apt-get update -y >/dev/null 2>&1 || warn "apt-get update had warnings"
    _apt_updated=1
  fi
}

apt_install() {
  [[ $DRY_RUN -eq 1 ]] && { dry "Would apt-get install: $*"; return 0; }
  apt_ensure_updated
  apt-get install -y "$@" >/dev/null 2>&1
}

# Purge packages with separate confirmation gate. (from v3.5)
apt_purge_with_confirm() {
  local pkgs=("$@")
  [[ ${#pkgs[@]} -eq 0 ]] && return 0

  echo ""
  warn "The following packages will be PURGED (config files removed):"
  warn "  ${pkgs[*]}"
  warn "This may affect other services that depend on these packages."
  echo -n "Proceed with package purge? [y/N] "
  read -r ans
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    info "Skipping package purge."
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get purge -y "${pkgs[@]}" >/dev/null 2>&1 || true
  apt-get autoremove -y >/dev/null 2>&1 || true
  info "Purged packages: ${pkgs[*]}"
}

# ═══════════════════════════════════════════════════
# §4  Detection helpers
# ═══════════════════════════════════════════════════
detect_boot_paths() {
  if [[ -d /boot/firmware ]]; then
    BOOT_DIR="/boot/firmware"
  elif [[ -d /boot ]]; then
    BOOT_DIR="/boot"
  else
    fail "Cannot find /boot or /boot/firmware"
  fi
  CONFIG_TXT="$BOOT_DIR/config.txt"
  CMDLINE_TXT="$BOOT_DIR/cmdline.txt"
  [[ -f "$CONFIG_TXT" ]]  || fail "Missing: $CONFIG_TXT"
  [[ -f "$CMDLINE_TXT" ]] || fail "Missing: $CMDLINE_TXT"
}

detect_upstream_iface() {
  if [[ "$UPSTREAM_IFACE" != "auto" ]]; then
    echo "$UPSTREAM_IFACE"; return 0
  fi
  local dev
  dev="$(ip route show default 2>/dev/null \
       | awk '/default/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  [[ -n "${dev:-}" ]] && { echo "$dev"; return 0; }
  ip link show wlan0 &>/dev/null && { echo "wlan0"; return 0; }
  ip link show eth0  &>/dev/null && { echo "eth0";  return 0; }
  echo ""
}

detect_pi_model() {
  if [[ ! -f /proc/device-tree/model ]]; then
    warn "No /proc/device-tree/model. Proceeding anyway."
    return 0
  fi
  local model
  model="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || true)"
  info "Detected: ${model:-unknown}"

  if echo "$model" | grep -qi "Pi Zero"; then
    info "Pi Zero family — USB gadget mode well-supported."
  elif echo "$model" | grep -qi "Pi 4"; then
    warn "Pi 4B — gadget over USB-C depends on correct port + data-capable cable."
  elif echo "$model" | grep -qi "Pi 5"; then
    warn "Pi 5 — gadget support limited/experimental. YMMV."
  else
    warn "Gadget mode support unknown for this model."
  fi
}

# ═══════════════════════════════════════════════════
# §5  Boot config (dwc2 + g_ether)
# ═══════════════════════════════════════════════════
_merge_cmdline_modules() {
  local file="$1"
  local line
  line="$(head -1 "$file")"

  if echo "$line" | grep -qE '(^| )modules-load='; then
    local current
    current="$(echo "$line" | sed -n 's/.*modules-load=\([^ ]*\).*/\1/p')"
    local merged="$current"

    list_contains_mod "$merged" "dwc2"    || merged="${merged},dwc2"
    list_contains_mod "$merged" "g_ether" || merged="${merged},g_ether"

    local newline
    newline="$(echo "$line" | sed -E "s/(modules-load=)[^ ]*/\1${merged}/")"
    echo "$newline" | atomic_write "$file"
    info "Merged modules-load=${merged} into cmdline.txt"
  else
    echo "${line} modules-load=dwc2,g_ether" | atomic_write "$file"
    info "Appended modules-load=dwc2,g_ether to cmdline.txt"
  fi
}

# Remove dwc2/g_ether from modules-load (pure awk, no paste dependency)
_remove_from_modules_load() {
  local line="$1"
  if ! echo "$line" | grep -qE '(^| )modules-load='; then
    echo "$line"; return 0
  fi

  local current
  current="$(echo "$line" | sed -n 's/.*modules-load=\([^ ]*\).*/\1/p')"

  local kept
  kept="$(echo "$current" | awk -F',' '{
    sep=""
    for (i=1; i<=NF; i++) {
      v = $i
      gsub(/^[ \t]+|[ \t]+$/, "", v)
      lv = tolower(v)
      if (lv != "dwc2" && lv != "g_ether" && v != "") {
        printf "%s%s", sep, v
        sep = ","
      }
    }
  }')"

  if [[ -z "${kept:-}" ]]; then
    echo "$line" | sed -E 's/(^| )modules-load=[^ ]*//' | sed 's/  */ /g; s/^ //'
  else
    echo "$line" | sed -E "s/(modules-load=)[^ ]*/\1${kept}/"
  fi
}

setup_boot_config() {
  [[ "$SKIP_BOOT" == "1" ]] && { warn "Skipping boot config (SKIP_BOOT=1)"; return 0; }
  step "Step 1: Enable USB gadget in boot config"

  detect_boot_paths
  info "Boot dir: $BOOT_DIR"

  if [[ $DRY_RUN -eq 1 ]]; then
    dry "Would backup $CONFIG_TXT and $CMDLINE_TXT"
  else
    backup_file "$CONFIG_TXT"
    backup_file "$CMDLINE_TXT"
  fi

  # config.txt overlay
  if grep -qE '^\s*dtoverlay=dwc2' "$CONFIG_TXT"; then
    info "config.txt: dtoverlay=dwc2 already present"
  else
    if [[ $DRY_RUN -eq 1 ]]; then
      dry "Would append dtoverlay=dwc2,dr_mode=peripheral to $CONFIG_TXT"
    else
      printf '\n# USB Gadget / OTG (iPad USB Ethernet)\ndtoverlay=dwc2,dr_mode=peripheral\n' \
        >> "$CONFIG_TXT"
      info "Added dtoverlay=dwc2,dr_mode=peripheral"
    fi
  fi

  # cmdline modules-load merge
  if grep -q "dwc2" "$CMDLINE_TXT" && grep -q "g_ether" "$CMDLINE_TXT"; then
    info "cmdline.txt: dwc2 + g_ether already present"
  else
    if [[ $DRY_RUN -eq 1 ]]; then
      dry "Would merge modules-load with dwc2,g_ether in $CMDLINE_TXT"
    else
      _merge_cmdline_modules "$CMDLINE_TXT"
    fi
  fi
}

# ═══════════════════════════════════════════════════
# §6  Static IP (NetworkManager / systemd-networkd)
# ═══════════════════════════════════════════════════
setup_usb_ip() {
  [[ "$SKIP_NETWORK" == "1" ]] && { warn "Skipping network config (SKIP_NETWORK=1)"; return 0; }

  local ip_cidr="${USB_IP}/${USB_PREFIX}"
  local con_name="ipad-${USB_IFACE}-static"

  if have_cmd nmcli && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    step "Step 2: Static IP on ${USB_IFACE} (NetworkManager)"
    if nmcli -t -f NAME connection show 2>/dev/null | grep -Fxq "$con_name"; then
      info "NM connection already exists: $con_name"
    else
      if [[ $DRY_RUN -eq 1 ]]; then
        dry "Would create NM connection: $con_name = $ip_cidr"
      else
        nmcli connection add \
          type ethernet ifname "$USB_IFACE" con-name "$con_name" \
          ipv4.addresses "$ip_cidr" ipv4.method manual ipv6.method disabled \
          >/dev/null
        CREATED_NM_CONNS+=("$con_name")
        info "Created NM connection: $con_name ($ip_cidr)"
      fi
    fi
    nmcli connection up "$con_name" 2>/dev/null || true
  else
    step "Step 2: Static IP on ${USB_IFACE} (systemd-networkd fallback)"
    local netfile="/etc/systemd/network/99-${USB_IFACE}-ipad.network"
    if [[ -f "$netfile" ]] && grep -q "Address=${ip_cidr}" "$netfile"; then
      info "networkd config already correct: $netfile"
    else
      if [[ $DRY_RUN -eq 1 ]]; then
        dry "Would write $netfile with Address=${ip_cidr}"
      else
        mkdir -p /etc/systemd/network
        cat <<EOF | managed_write_file "$netfile"
[Match]
Name=${USB_IFACE}

[Network]
Address=${ip_cidr}
IPv6AcceptRA=no
EOF
        info "Wrote: $netfile"
        service_record_prev_state systemd-networkd
        systemctl enable --now systemd-networkd >/dev/null 2>&1 || true
      fi
    fi
  fi
}

# ═══════════════════════════════════════════════════
# §7  dnsmasq DHCP
# ═══════════════════════════════════════════════════
setup_dnsmasq() {
  [[ "$SKIP_NETWORK" == "1" ]] && { warn "Skipping dnsmasq (SKIP_NETWORK=1)"; return 0; }
  step "Step 3: dnsmasq DHCP on ${USB_IFACE}"

  local conf="/etc/dnsmasq.d/${USB_IFACE}-ipad.conf"

  if [[ $DRY_RUN -eq 1 ]]; then
    dry "Would install dnsmasq and write $conf"
    return 0
  fi

  apt_install dnsmasq
  info "dnsmasq installed"

  cat <<EOF | managed_write_file "$conf"
# Auto-generated by rpi-ipad-otg-setup v${SCRIPT_VERSION}
# DHCP for iPad over ${USB_IFACE}
interface=${USB_IFACE}
bind-interfaces
except-interface=lo

dhcp-range=${DHCP_START},${DHCP_END},${USB_NETMASK},${DHCP_LEASE}
dhcp-option=3,${USB_IP}
dhcp-option=6,${DNS1},${DNS2}

log-dhcp
EOF

  service_record_prev_state dnsmasq
  systemctl enable dnsmasq >/dev/null 2>&1 || true
  systemctl restart dnsmasq
  info "dnsmasq serving ${DHCP_START}–${DHCP_END} on ${USB_IFACE}"

  systemctl is-active --quiet dnsmasq \
    || warn "dnsmasq failed to start — check: journalctl -u dnsmasq"
}

# ═══════════════════════════════════════════════════
# §8  IPv4 forwarding
# ═══════════════════════════════════════════════════
setup_ip_forwarding() {
  [[ "$SKIP_NAT" == "1" ]] && { warn "Skipping IP forwarding (SKIP_NAT=1)"; return 0; }
  step "Step 4: IPv4 forwarding"

  local sysctl_conf="/etc/sysctl.d/99-ipad-ipforward.conf"

  if [[ $DRY_RUN -eq 1 ]]; then
    dry "Would enable net.ipv4.ip_forward=1 and write $sysctl_conf"
    return 0
  fi

  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo "net.ipv4.ip_forward=1" | managed_write_file "$sysctl_conf"

  sysctl --system >/dev/null 2>&1 || true
  info "IPv4 forwarding enabled"

  local val
  val="$(cat /proc/sys/net/ipv4/ip_forward)"
  [[ "$val" == "1" ]] && info "Verified: ip_forward = 1" \
                       || warn "ip_forward is $val (expected 1)"
}

# ═══════════════════════════════════════════════════
# §9  nftables NAT + forward
# ═══════════════════════════════════════════════════
setup_nftables() {
  [[ "$SKIP_NAT" == "1" ]] && { warn "Skipping nftables (SKIP_NAT=1)"; return 0; }

  UPSTREAM="$(detect_upstream_iface)"
  [[ -n "$UPSTREAM" ]] || fail "Cannot detect upstream interface. Set UPSTREAM_IFACE=wlan0|eth0."

  step "Step 5: nftables NAT (${USB_IFACE} → ${UPSTREAM})"

  # Dynamic filename based on USB_IFACE (from v3.6)
  local rules_dir="/etc/nftables.d"
  local rules_file="${rules_dir}/ipad-${USB_IFACE}.nft"
  local main="/etc/nftables.conf"
  local include_line='include "/etc/nftables.d/*.nft"'

  if [[ $DRY_RUN -eq 1 ]]; then
    dry "Would install nftables"
    dry "Would write $rules_file (${USB_SUBNET_CIDR} → ${UPSTREAM})"
    dry "Would ensure $main includes drop-in dir"
    return 0
  fi

  apt_install nftables
  mkdir -p "$rules_dir"

  # Delete existing table in bash (not in .nft — shell syntax ≠ nft syntax)
  nft delete table inet ipad_nat >/dev/null 2>&1 || true

  cat <<EOF | managed_write_file "$rules_file"
# Auto-generated by rpi-ipad-otg-setup v${SCRIPT_VERSION}
# iPad (${USB_IFACE} / ${USB_SUBNET_CIDR}) → upstream (${UPSTREAM})

table inet ipad_nat {
  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept
    iifname "${USB_IFACE}" ip saddr ${USB_SUBNET_CIDR} oifname "${UPSTREAM}" accept
  }

  chain postrouting {
    type nat hook postrouting priority 100;
    oifname "${UPSTREAM}" ip saddr ${USB_SUBNET_CIDR} masquerade
  }
}
EOF

  # Ensure main nftables.conf includes drop-in directory
  if [[ ! -f "$main" ]]; then
    cat <<'EOF' | managed_write_file "$main"
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
    info "Created $main"
  elif ! grep -qF "$include_line" "$main"; then
    backup_file "$main"
    printf '\n# Load drop-in rules\n%s\n' "$include_line" >> "$main"
    info "Appended include directive to $main"
  else
    info "$main already includes drop-in directory"
  fi

  service_record_prev_state nftables
  systemctl enable nftables >/dev/null 2>&1 || true
  systemctl restart nftables

  if nft list table inet ipad_nat >/dev/null 2>&1; then
    info "nftables verified (table inet ipad_nat loaded)"
  else
    warn "nftables table ipad_nat not found — check: nft list ruleset"
  fi
}

# ═══════════════════════════════════════════════════
# §10 tmux
# ═══════════════════════════════════════════════════
setup_tmux() {
  [[ "$INSTALL_TMUX" != "1" ]] && { warn "Skipping tmux (INSTALL_TMUX=0)"; return 0; }
  step "Step 6: tmux"
  apt_install tmux
  info "tmux installed"
}

# ═══════════════════════════════════════════════════
# §11 Samba (hardened)
# ═══════════════════════════════════════════════════
_warn_samba_pass_leak() {
  if [[ -n "${SAMBA_PASS:-}" ]]; then
    warn "SAMBA_PASS was passed via environment variable."
    warn "Env vars can leak via /proc/\$\$/environ or process listings."
    warn "Consider using an interactive prompt or root-readable secrets file in production."
    info "SAMBA_PASS will be unset from environment after use."
  fi
}

setup_samba() {
  [[ "$INSTALL_SAMBA" != "1" ]] && { warn "Skipping Samba (INSTALL_SAMBA=0)"; return 0; }
  step "Step 7: Samba share (hardened, ${USB_IFACE}-only)"

  _warn_samba_pass_leak
  apt_install samba

  # Dedicated system user
  if ! id "$SAMBA_USER" &>/dev/null; then
    if [[ $DRY_RUN -eq 1 ]]; then
      dry "Would create system user: $SAMBA_USER"
    else
      useradd --system --create-home --shell /usr/sbin/nologin "$SAMBA_USER"
      CREATED_USERS+=("$SAMBA_USER")
      info "Created system user: $SAMBA_USER"
    fi
  else
    info "User exists: $SAMBA_USER"
  fi

  # Share directory (SGID, not world-writable)
  if [[ $DRY_RUN -eq 1 ]]; then
    dry "Would create dir $SAMBA_SHARE_DIR (mode 2770)"
  else
    mkdir -p "$SAMBA_SHARE_DIR"
    chown "${SAMBA_USER}:${SAMBA_USER}" "$SAMBA_SHARE_DIR"
    chmod 2770 "$SAMBA_SHARE_DIR"
    info "Share dir: $SAMBA_SHARE_DIR (mode 2770)"
  fi

  # Dynamic marker based on USB_IFACE (from v3.6)
  local smb="/etc/samba/smb.conf"
  local marker_begin="### BEGIN IPAD-${USB_IFACE}-V3 ###"
  local marker_end="### END IPAD-${USB_IFACE}-V3 ###"

  if [[ $DRY_RUN -eq 1 ]]; then
    dry "Would manage block in $smb and configure [ipadshare]"
    return 0
  fi

  backup_file "$smb"

  # Remove current managed block if present
  if grep -qF "$marker_begin" "$smb"; then
    sed -i "\|${marker_begin}|,\|${marker_end}|d" "$smb"
    info "Removed previous managed block"
  fi

  # Legacy cleanup: v3.0–v3.5 used hardcoded "IPAD-USB0-V3" markers
  if grep -qF "### BEGIN IPAD-USB0-V3 ###" "$smb"; then
    sed -i '\|### BEGIN IPAD-USB0-V3 ###|,\|### END IPAD-USB0-V3 ###|d' "$smb"
    info "Removed legacy managed block (usb0)"
  fi

  cat >> "$smb" <<EOF

${marker_begin}
# Auto-generated by rpi-ipad-otg-setup v${SCRIPT_VERSION}
interfaces = ${USB_IFACE} lo
bind interfaces only = yes
hosts allow = ${USB_SUBNET_CIDR} 127.0.0.1
hosts deny = 0.0.0.0/0
map to guest = Never
smb ports = 445

[ipadshare]
   path = ${SAMBA_SHARE_DIR}
   browseable = yes
   read only = no
   create mask = 0660
   directory mask = 2770
   valid users = ${SAMBA_USER}
EOF

  if [[ "$ENABLE_GUEST_SAMBA" == "1" ]]; then
    warn "Guest mode enabled (ENABLE_GUEST_SAMBA=1). Still subnet-restricted."
    cat >> "$smb" <<EOF
   guest ok = yes
   public = yes
EOF
  fi

  echo "$marker_end" >> "$smb"
  info "Wrote Samba managed block"

  # Samba password
  if [[ "$ENABLE_GUEST_SAMBA" != "1" ]]; then
    if pdbedit -L 2>/dev/null | awk -F: '{print $1}' | grep -Fxq "$SAMBA_USER"; then
      info "Samba user already in passdb: $SAMBA_USER"
    elif [[ -n "${SAMBA_PASS:-}" ]]; then
      printf '%s\n%s\n' "$SAMBA_PASS" "$SAMBA_PASS" | smbpasswd -s -a "$SAMBA_USER"
      smbpasswd -e "$SAMBA_USER" >/dev/null 2>&1
      info "Samba password set (non-interactive) for: $SAMBA_USER"
    else
      warn "No SAMBA_PASS set. Interactive password prompt..."
      smbpasswd -a "$SAMBA_USER"
      smbpasswd -e "$SAMBA_USER" >/dev/null 2>&1
      info "Samba password set for: $SAMBA_USER"
    fi
  fi

  # Scrub password from environment
  unset SAMBA_PASS 2>/dev/null || true

  service_record_prev_state smbd
  systemctl enable smbd >/dev/null 2>&1 || true
  systemctl restart smbd

  systemctl is-active --quiet smbd \
    && info "smbd is running" \
    || warn "smbd failed — check: journalctl -u smbd"
}

# ═══════════════════════════════════════════════════
# §12 --check: Post-reboot health validation (eval-free)
#
# Each check is a named function. _check() calls it by reference.
# No eval is used anywhere — eliminates injection surface. (from v3.5)
# ═══════════════════════════════════════════════════

# ── Individual check functions ──
_chk_dwc2()              { lsmod | grep -qw dwc2; }
_chk_g_ether()           { lsmod | grep -qw g_ether; }
_chk_iface_exists()      { ip link show "$USB_IFACE"; }
# Exact match on IPv4 address/prefix — avoids false positives (from v3.6)
_chk_iface_has_ip()      {
  ip -o -4 addr show dev "$USB_IFACE" 2>/dev/null \
    | awk '{print $4}' \
    | grep -Fxq "${USB_IP}/${USB_PREFIX}"
}
_chk_dnsmasq_running()   { systemctl is-active --quiet dnsmasq; }
_chk_dnsmasq_conf_bind() {
  grep -Eq "^[[:space:]]*interface=${USB_IFACE}[[:space:]]*$" \
    "/etc/dnsmasq.d/${USB_IFACE}-ipad.conf"
}
# Robust: check UDP/67 by dnsmasq process, not IP-specific (from v3.5)
_chk_dnsmasq_udp67()     {
  ss -ulnp | awk '($5 ~ /:67$/) && ($0 ~ /dnsmasq/){ok=1} END{exit !ok}'
}
_chk_ip_forward()        { [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; }
_chk_nft_table()         { nft list table inet ipad_nat; }
# Version-tolerant regex for nft output (from v3.5)
_chk_nft_policy_drop()   {
  nft list chain inet ipad_nat forward | grep -Eq 'policy[[:space:]]+drop'
}
_chk_nft_masquerade()    {
  nft list chain inet ipad_nat postrouting | grep -Eq '\bmasquerade\b'
}
_chk_smbd_running()      { systemctl is-active --quiet smbd; }
_chk_share_dir_exists()  { [[ -d "$SAMBA_SHARE_DIR" ]]; }
_chk_smb_bind_iface()    {
  grep -Eq '^[[:space:]]*bind interfaces only[[:space:]]*=[[:space:]]*yes' /etc/samba/smb.conf
}
_chk_samba_passdb()      {
  pdbedit -L 2>/dev/null | awk -F: '{print $1}' | grep -Fxq "$SAMBA_USER"
}

# ── Check runner (no eval) ──
_hc_pass=0
_hc_total=0

_check() {
  local label="$1"
  local func="$2"
  _hc_total=$(( _hc_total + 1 ))
  if "$func" >/dev/null 2>&1; then
    info "PASS: $label"
    _hc_pass=$(( _hc_pass + 1 ))
  else
    warn "FAIL: $label"
  fi
}

run_health_check() {
  step "Health Check: Post-reboot validation"
  _hc_pass=0
  _hc_total=0

  echo ""
  echo -e "${C_BOLD}── Kernel modules ──${C_NC}"
  _check "dwc2 module loaded"                _chk_dwc2
  _check "g_ether module loaded"             _chk_g_ether

  echo -e "${C_BOLD}── Network interface ──${C_NC}"
  _check "${USB_IFACE} exists"               _chk_iface_exists
  _check "${USB_IFACE} has IP ${USB_IP}/${USB_PREFIX}" _chk_iface_has_ip

  echo -e "${C_BOLD}── DHCP (dnsmasq) ──${C_NC}"
  _check "dnsmasq running"                   _chk_dnsmasq_running
  _check "dnsmasq config binds ${USB_IFACE}" _chk_dnsmasq_conf_bind
  _check "dnsmasq listening on UDP 67"       _chk_dnsmasq_udp67

  echo -e "${C_BOLD}── IP forwarding ──${C_NC}"
  _check "ip_forward = 1"                    _chk_ip_forward

  echo -e "${C_BOLD}── nftables ──${C_NC}"
  _check "nftables ipad_nat table"           _chk_nft_table
  _check "forward chain policy drop"         _chk_nft_policy_drop
  _check "masquerade rule present"           _chk_nft_masquerade

  if [[ "$INSTALL_SAMBA" == "1" ]]; then
    echo -e "${C_BOLD}── Samba ──${C_NC}"
    _check "smbd running"                    _chk_smbd_running
    _check "Share dir exists"                _chk_share_dir_exists
    _check "smb.conf binds ${USB_IFACE} only" _chk_smb_bind_iface
    _check "Samba user in passdb"            _chk_samba_passdb
  fi

  echo ""
  if [[ $_hc_pass -eq $_hc_total ]]; then
    info "All checks passed (${_hc_pass}/${_hc_total}) ✨"
  else
    warn "${_hc_pass}/${_hc_total} checks passed. Review FAILs above."
    warn "Tip: journalctl -u <service> for details on failed services."
  fi
}

# ═══════════════════════════════════════════════════
# §13 --uninstall / --purge
# ═══════════════════════════════════════════════════
remove_boot_changes() {
  detect_boot_paths
  step "Uninstall (boot): Removing dwc2 overlay and modules-load entries"

  if [[ -f "$CONFIG_TXT" ]]; then
    backup_file "$CONFIG_TXT"
    sed -i \
      -e '/# USB Gadget \/ OTG (iPad USB Ethernet)/d' \
      -e '/^dtoverlay=dwc2,dr_mode=peripheral$/d' \
      "$CONFIG_TXT" || true
    info "Updated $CONFIG_TXT (removed dwc2 overlay)"
  fi

  if [[ -f "$CMDLINE_TXT" ]]; then
    backup_file "$CMDLINE_TXT"
    local line new
    line="$(head -1 "$CMDLINE_TXT")"
    new="$(_remove_from_modules_load "$line")"
    echo "$new" | atomic_write "$CMDLINE_TXT"
    info "Updated $CMDLINE_TXT (removed dwc2/g_ether)"
  fi
}

run_uninstall() {
  step "Uninstall: Reversing iPad OTG setup"

  warn "This will remove dnsmasq/nftables rules, IP forward config, network config, and Samba block."
  if [[ $UNINSTALL_REMOVE_BOOT -eq 1 ]]; then
    warn "Boot config changes WILL also be removed (--remove-boot)."
  else
    warn "Boot config will NOT be removed (add --remove-boot to include)."
  fi
  if [[ $PURGE_MODE -eq 1 ]]; then
    warn "PURGE enabled: will also remove ${SAMBA_USER}, ${SAMBA_SHARE_DIR}, and offer to purge packages."
  fi

  echo -n "Proceed with uninstall? [y/N] "
  read -r ans
  [[ "$ans" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }

  # nftables — clean both dynamic and legacy filenames (from v3.6)
  rm -f "/etc/nftables.d/ipad-${USB_IFACE}.nft" "/etc/nftables.d/ipad-usb0.nft"
  nft delete table inet ipad_nat 2>/dev/null || true
  systemctl restart nftables 2>/dev/null || true
  info "Removed nftables rules"

  # sysctl
  rm -f /etc/sysctl.d/99-ipad-ipforward.conf
  sysctl --system >/dev/null 2>&1 || true
  info "Removed IP forwarding config"

  # dnsmasq
  rm -f "/etc/dnsmasq.d/${USB_IFACE}-ipad.conf"
  systemctl restart dnsmasq 2>/dev/null || true
  info "Removed dnsmasq config"

  # Network config
  local con_name="ipad-${USB_IFACE}-static"
  if have_cmd nmcli; then
    nmcli connection delete "$con_name" 2>/dev/null || true
  fi
  rm -f "/etc/systemd/network/99-${USB_IFACE}-ipad.network"
  systemctl restart systemd-networkd 2>/dev/null || true
  info "Removed network config"

  # Samba managed block — dynamic marker + legacy cleanup (from v3.6)
  local smb="/etc/samba/smb.conf"
  local marker_begin="### BEGIN IPAD-${USB_IFACE}-V3 ###"
  local marker_end="### END IPAD-${USB_IFACE}-V3 ###"

  if [[ -f "$smb" ]]; then
    if grep -qF "$marker_begin" "$smb"; then
      sed -i "\|${marker_begin}|,\|${marker_end}|d" "$smb"
      info "Removed Samba managed block (${USB_IFACE})"
    fi
    # Legacy cleanup
    if grep -qF "### BEGIN IPAD-USB0-V3 ###" "$smb"; then
      sed -i '\|### BEGIN IPAD-USB0-V3 ###|,\|### END IPAD-USB0-V3 ###|d' "$smb"
      info "Removed legacy Samba managed block (usb0)"
    fi
    systemctl restart smbd 2>/dev/null || true
  fi

  # Boot (optional)
  if [[ $UNINSTALL_REMOVE_BOOT -eq 1 ]]; then
    remove_boot_changes
  fi

  # Purge (optional, with separate confirmation) (from v3.5)
  if [[ $PURGE_MODE -eq 1 ]]; then
    step "Purge: removing user, share directory, and packages"

    # Remove Samba passdb entry + system user
    if id "$SAMBA_USER" >/dev/null 2>&1; then
      pdbedit -x -u "$SAMBA_USER" >/dev/null 2>&1 || true
      userdel "$SAMBA_USER" >/dev/null 2>&1 || true
      info "Purged user: $SAMBA_USER"
    else
      info "User not present: $SAMBA_USER (nothing to remove)"
    fi

    # Remove share directory
    if [[ -n "$SAMBA_SHARE_DIR" && -d "$SAMBA_SHARE_DIR" ]]; then
      rm -rf "$SAMBA_SHARE_DIR" 2>/dev/null || true
      info "Purged share dir: $SAMBA_SHARE_DIR"
    fi

    # Package purge with its own confirmation gate
    apt_purge_with_confirm samba dnsmasq nftables tmux
  fi

  info "Uninstall complete. Reboot recommended."
}

# ═══════════════════════════════════════════════════
# §14 CLI argument parsing + validation
# ═══════════════════════════════════════════════════
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)      DRY_RUN=1 ;;
      --check)        CHECK_MODE=1 ;;
      --uninstall)    UNINSTALL_MODE=1 ;;
      --remove-boot)  UNINSTALL_REMOVE_BOOT=1 ;;
      --purge)        PURGE_MODE=1 ;;
      --version|-V)
        echo "rpi-ipad-otg-setup v${SCRIPT_VERSION}"
        exit 0
        ;;
      --help|-h)
        cat <<'HELPEOF'
Usage: sudo ./rpi-ipad-otg-setup.v3.7.sh [OPTIONS]

Options:
  --dry-run       Preview all changes without applying them
  --check         Post-reboot health validation (run after reboot)
  --uninstall     Reverse all runtime changes (configs, rules, NM)
  --remove-boot   With --uninstall: also revert boot config edits
  --purge         With --uninstall: also remove user/share dir + offer pkg purge
  --version, -V   Print version and exit
  --help, -h      Show this help

Environment overrides (see header of script for full list):
  USB_IP=10.55.0.1  USB_PREFIX=29  UPSTREAM_IFACE=wlan0
  SAMBA_PASS=secret  INSTALL_SAMBA=0  SKIP_BOOT=1  ...

Examples:
  sudo ./rpi-ipad-otg-setup.v3.7.sh                              # full install
  sudo ./rpi-ipad-otg-setup.v3.7.sh --dry-run                    # preview
  sudo USB_IFACE=usb1 ./rpi-ipad-otg-setup.v3.7.sh              # alt iface
  sudo UPSTREAM_IFACE=eth0 ./rpi-ipad-otg-setup.v3.7.sh          # use eth0
  sudo ./rpi-ipad-otg-setup.v3.7.sh --check                      # health check
  sudo ./rpi-ipad-otg-setup.v3.7.sh --uninstall                  # remove configs
  sudo ./rpi-ipad-otg-setup.v3.7.sh --uninstall --remove-boot --purge
HELPEOF
        exit 0
        ;;
      *)
        warn "Unknown option: $1 (try --help)"
        ;;
    esac
    shift
  done

  # Flag combination validation (from v3.5)
  if [[ $PURGE_MODE -eq 1 && $UNINSTALL_MODE -eq 0 ]]; then
    fail "--purge requires --uninstall. Usage: sudo $0 --uninstall --purge"
  fi
  if [[ $UNINSTALL_REMOVE_BOOT -eq 1 && $UNINSTALL_MODE -eq 0 ]]; then
    fail "--remove-boot requires --uninstall. Usage: sudo $0 --uninstall --remove-boot"
  fi
}

# ═══════════════════════════════════════════════════
# §15 main()
# ═══════════════════════════════════════════════════
main() {
  parse_args "$@"

  echo -e "${C_CYAN}╔══════════════════════════════════════════════╗${C_NC}"
  echo -e "${C_CYAN}║  RPi ↔ iPad USB OTG Setup  v${SCRIPT_VERSION}           ║${C_NC}"
  echo -e "${C_CYAN}╚══════════════════════════════════════════════╝${C_NC}"

  if [[ "${EUID}" -ne 0 ]]; then
    fail "Please run with sudo: sudo $0"
  fi

  # Compute netmask from prefix
  USB_NETMASK="$(cidr_to_netmask "$USB_PREFIX")"
  info "USB subnet: ${USB_IP}/${USB_PREFIX} (netmask ${USB_NETMASK})"

  # Subnet sanity check: runs for install + dry-run (catch errors early),
  # skipped for --check and --uninstall where subnet config doesn't matter.
  if [[ $CHECK_MODE -eq 0 && $UNINSTALL_MODE -eq 0 ]]; then
    validate_usb_subnet_sanity
  fi

  # Dispatch modes
  if [[ $CHECK_MODE -eq 1 ]]; then
    run_health_check
    exit 0
  fi
  if [[ $UNINSTALL_MODE -eq 1 ]]; then
    run_uninstall
    exit 0
  fi

  # Normal install
  acquire_lock
  RUN_START_EPOCH="$(date +%s)"
  _log "=== Run started (v${SCRIPT_VERSION}) ==="

  [[ $DRY_RUN -eq 1 ]] && warn "DRY-RUN mode: no changes will be made"

  step "Pre-flight"
  detect_pi_model
  UPSTREAM="$(detect_upstream_iface)"
  info "Upstream interface: ${UPSTREAM:-<none detected>}"

  setup_boot_config
  setup_usb_ip
  setup_dnsmasq
  setup_ip_forwarding
  setup_nftables
  setup_tmux
  setup_samba

  # Elapsed time
  local elapsed="?"
  if [[ -n "$RUN_START_EPOCH" ]]; then
    local now
    now="$(date +%s)"
    elapsed="$(( now - RUN_START_EPOCH ))s"
  fi

  # Summary
  echo ""
  echo -e "${C_GREEN}╔══════════════════════════════════════════════╗${C_NC}"
  echo -e "${C_GREEN}║  Setup complete! Reboot to activate.        ║${C_NC}"
  echo -e "${C_GREEN}╚══════════════════════════════════════════════╝${C_NC}"
  echo ""
  echo "  Pi USB IP         : ${USB_IP}/${USB_PREFIX} (${USB_NETMASK})"
  echo "  iPad DHCP range   : ${DHCP_START} – ${DHCP_END} (lease ${DHCP_LEASE})"
  echo "  Upstream NAT      : ${UPSTREAM}"
  echo "  DNS for iPad      : ${DNS1}, ${DNS2}"
  if [[ "$INSTALL_SAMBA" == "1" ]]; then
    echo "  Samba share       : \\\\${USB_IP}\\ipadshare"
    echo "  Share directory   : ${SAMBA_SHARE_DIR}"
    echo "  Samba user        : ${SAMBA_USER}"
  fi
  echo "  SSH               : ssh <user>@${USB_IP}"
  echo ""
  echo "  Elapsed           : ${elapsed}"
  echo "  Logs              : ${LOG_FILE}"
  echo ""
  echo "  Post-reboot       : sudo $0 --check"
  echo "  Uninstall         : sudo $0 --uninstall [--remove-boot] [--purge]"
  echo ""
  warn "Reboot now: sudo reboot"

  _log "=== Run completed successfully (${elapsed}) ==="
}

main "$@"
