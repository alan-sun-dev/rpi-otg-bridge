# rpi-otg-bridge

Turn your Raspberry Pi into a USB Ethernet gadget — plug it into an iPad (or any USB host) and get instant SSH, internet sharing, and file transfer over a single cable.

One script. One cable. Full workstation.

## What It Does

```
┌─────────┐   USB-C Cable   ┌──────────────┐   Wi-Fi/Ethernet   ┌──────────┐
│  iPad    │◄───────────────►│  Raspberry Pi │◄──────────────────►│ Internet │
│          │  USB Ethernet   │              │    NAT + Forward    │          │
│  SSH     │  10.55.0.0/29   │  dnsmasq     │                    │          │
│  Samba   │                 │  nftables    │                    │          │
│  Browse  │                 │  smbd        │                    │          │
└─────────┘                  └──────────────┘                    └──────────┘
```

The setup script configures your Pi as a USB Ethernet gadget using the `dwc2` / `g_ether` kernel modules, then layers on DHCP, NAT, firewall rules, and an optional Samba file share — all locked down to the USB subnet.

## Features

- **Single-script setup** — one `sudo` command configures everything
- **Idempotent** — safe to re-run; detects existing config and skips
- **Atomic writes** — config files are written atomically (no half-written states)
- **Full rollback** — if anything fails mid-run, all changes are automatically reverted
- **Dry-run mode** — preview every change before applying
- **Health check** — post-reboot validation confirms all services are working
- **Clean uninstall** — reverse all changes, optionally including boot config and packages
- **Portable** — auto-detects boot paths (Bookworm vs legacy), network manager (NetworkManager vs systemd-networkd), and upstream interface
- **Hardened** — nftables with `policy drop`, Samba bound to USB interface only, subnet-restricted access, no world-writable directories
- **Fully parameterized** — every setting is overridable via environment variables

## Compatibility

| Board | Status | Notes |
|-------|--------|-------|
| Pi Zero / Zero W / Zero 2 W | ✅ Best supported | Native USB gadget via micro-USB |
| Pi 4 Model B | ✅ Works | Gadget mode via USB-C port (use data-capable cable) |
| Pi 5 | ⚠️ Experimental | Limited gadget support; YMMV |

**Host side:** Tested with iPad (iPadOS 15+), also works with macOS, Linux, and Windows as USB host.

**OS:** Raspberry Pi OS Bookworm (64-bit) recommended. Also works on Bullseye and Lite variants.

## Quick Start

```bash
# 1. Clone
git clone https://github.com/<your-username>/rpi-otg-bridge.git
cd rpi-otg-bridge

# 2. Preview (optional)
sudo ./rpi-otg-bridge.sh --dry-run

# 3. Install
sudo ./rpi-otg-bridge.sh

# 4. Reboot
sudo reboot

# 5. Validate
sudo ./rpi-otg-bridge.sh --check
```

After reboot, connect your iPad to the Pi via USB-C. The iPad will receive an IP via DHCP (default `10.55.0.2`), and you can:

```bash
# SSH from iPad (using Termius, Blink, etc.)
ssh pi@10.55.0.1

# Access Samba share (Files app → Connect to Server)
smb://10.55.0.1/ipadshare

# Browse the internet through the Pi's Wi-Fi/Ethernet uplink
```

## Usage

```
Usage: sudo ./rpi-otg-bridge.sh [OPTIONS]

Options:
  --dry-run       Preview all changes without applying them
  --check         Post-reboot health validation
  --uninstall     Reverse all runtime changes (configs, rules, NM connections)
  --remove-boot   With --uninstall: also revert boot config (dtoverlay, modules-load)
  --purge         With --uninstall: also remove user/share dir + offer to purge packages
  --version, -V   Print version and exit
  --help, -h      Show help
```

### Examples

```bash
# Standard install with defaults
sudo ./rpi-otg-bridge.sh

# Preview what would change
sudo ./rpi-otg-bridge.sh --dry-run

# Use a specific upstream interface
sudo UPSTREAM_IFACE=eth0 ./rpi-otg-bridge.sh

# Custom subnet and non-interactive Samba password
sudo USB_IP=192.168.100.1 USB_PREFIX=24 \
     USB_SUBNET_CIDR=192.168.100.0/24 \
     DHCP_START=192.168.100.10 DHCP_END=192.168.100.50 \
     SAMBA_PASS=mysecret ./rpi-otg-bridge.sh

# Skip Samba and tmux
sudo INSTALL_SAMBA=0 INSTALL_TMUX=0 ./rpi-otg-bridge.sh

# Use a different USB interface name
sudo USB_IFACE=usb1 ./rpi-otg-bridge.sh

# Health check after reboot
sudo ./rpi-otg-bridge.sh --check

# Full removal (configs + boot + packages)
sudo ./rpi-otg-bridge.sh --uninstall --remove-boot --purge
```

## Configuration

All settings have sensible defaults and can be overridden via environment variables:

### Network

| Variable | Default | Description |
|----------|---------|-------------|
| `USB_IFACE` | `usb0` | USB gadget interface name |
| `USB_IP` | `10.55.0.1` | Pi's static IP on USB interface |
| `USB_PREFIX` | `29` | CIDR prefix (29 = 6 usable hosts) |
| `USB_SUBNET_CIDR` | `10.55.0.0/29` | Subnet for firewall rules |
| `DHCP_START` | `10.55.0.2` | DHCP range start |
| `DHCP_END` | `10.55.0.6` | DHCP range end |
| `DHCP_LEASE` | `12h` | DHCP lease duration |
| `DNS1` / `DNS2` | `1.1.1.1` / `8.8.8.8` | DNS servers pushed to client |
| `UPSTREAM_IFACE` | `auto` | Upstream interface for NAT (`auto` = auto-detect) |

### Services

| Variable | Default | Description |
|----------|---------|-------------|
| `INSTALL_TMUX` | `1` | Install tmux (`0` to skip) |
| `INSTALL_SAMBA` | `1` | Install and configure Samba (`0` to skip) |
| `SAMBA_USER` | `ipadshare` | Dedicated Samba system user |
| `SAMBA_SHARE_DIR` | `/srv/ipad-share` | Shared directory path |
| `SAMBA_PASS` | _(empty)_ | Non-interactive password (prompts if empty) |
| `ENABLE_GUEST_SAMBA` | `0` | Allow guest access (`1` = yes, still subnet-restricted) |

### Skip Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `SKIP_BOOT` | `0` | Skip boot config modifications |
| `SKIP_NETWORK` | `0` | Skip static IP + DHCP setup |
| `SKIP_NAT` | `0` | Skip IP forwarding + nftables |

## What Gets Installed / Changed

The script touches the following (all reversible via `--uninstall`):

| Component | Files | Service |
|-----------|-------|---------|
| Boot config | `/boot/firmware/config.txt`, `cmdline.txt` | _(reboot required)_ |
| Static IP | NM connection or `/etc/systemd/network/99-usb0-ipad.network` | NetworkManager / systemd-networkd |
| DHCP | `/etc/dnsmasq.d/usb0-ipad.conf` | dnsmasq |
| IP forwarding | `/etc/sysctl.d/99-ipad-ipforward.conf` | sysctl |
| Firewall | `/etc/nftables.d/ipad-usb0.nft` | nftables |
| File sharing | Managed block in `/etc/samba/smb.conf` | smbd |

> File paths shown with default `USB_IFACE=usb0`. With custom interface names, filenames adapt accordingly.

## Health Check

After reboot, run `--check` to verify everything is working:

```
━━━ Health Check: Post-reboot validation ━━━

── Kernel modules ──
[✓] PASS: dwc2 module loaded
[✓] PASS: g_ether module loaded
── Network interface ──
[✓] PASS: usb0 exists
[✓] PASS: usb0 has IP 10.55.0.1/29
── DHCP (dnsmasq) ──
[✓] PASS: dnsmasq running
[✓] PASS: dnsmasq config binds usb0
[✓] PASS: dnsmasq listening on UDP 67
── IP forwarding ──
[✓] PASS: ip_forward = 1
── nftables ──
[✓] PASS: nftables ipad_nat table
[✓] PASS: forward chain policy drop
[✓] PASS: masquerade rule present
── Samba ──
[✓] PASS: smbd running
[✓] PASS: Share dir exists
[✓] PASS: smb.conf binds usb0 only
[✓] PASS: Samba user in passdb

[✓] All checks passed (15/15) ✨
```

## Security Design

- **Firewall**: nftables with `policy drop` on forward chain — only USB subnet → upstream is allowed
- **Samba**: bound to USB interface only (`bind interfaces only = yes`), `hosts allow` restricted to USB subnet + localhost, `map to guest = Never`
- **Share permissions**: directory mode `2770` (SGID), create mask `0660` — no world-readable files
- **System user**: dedicated `ipadshare` user with `/usr/sbin/nologin` shell (no SSH access)
- **SAMBA_PASS**: warning issued if passed via env var; scrubbed from environment after use

## Rollback

If the script fails at any point, the EXIT trap automatically:

1. Restores all modified files from timestamped backups
2. Removes any files created during the run
3. Deletes NetworkManager connections that were added
4. Reverts service enable/disable states
5. Removes system users that were created

No manual cleanup needed.

## Troubleshooting

**iPad doesn't get an IP:**
- Ensure you're using a USB-C cable that supports data (not charge-only)
- On Pi 4, use the USB-C port (not the USB-A ports)
- Check: `ip link show usb0` — if no interface, reboot may be needed
- Check: `journalctl -u dnsmasq` for DHCP errors

**Can't browse the internet from iPad:**
- Verify upstream: `ip route show default` should show your Wi-Fi/Ethernet interface
- Check forwarding: `cat /proc/sys/net/ipv4/ip_forward` should be `1`
- Check NAT: `sudo nft list table inet ipad_nat`

**Samba share not visible:**
- From iPad Files app: Connect to Server → `smb://10.55.0.1`
- Check: `sudo systemctl status smbd`
- Test locally: `smbclient //10.55.0.1/ipadshare -U ipadshare`

**Health check fails after reboot:**
- Run `sudo ./rpi-otg-bridge.sh --check` and follow the FAIL hints
- Most issues are resolved by re-running the install script

## Uninstall

```bash
# Remove runtime configs (keeps boot changes)
sudo ./rpi-otg-bridge.sh --uninstall

# Remove everything including boot config
sudo ./rpi-otg-bridge.sh --uninstall --remove-boot

# Nuclear option: remove configs + user + share dir + purge packages
sudo ./rpi-otg-bridge.sh --uninstall --remove-boot --purge
```

## Requirements

- Raspberry Pi with USB OTG support (Zero, Zero W, Zero 2 W, 4B, or 5)
- Raspberry Pi OS (Bookworm or Bullseye)
- USB-C or micro-USB data cable
- Root access (`sudo`)

No external dependencies beyond what's available in the default Raspberry Pi OS repositories (`dnsmasq`, `nftables`, `samba`, `tmux`).

## License

MIT

