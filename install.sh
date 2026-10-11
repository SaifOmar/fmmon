#!/usr/bin/env bash
# fmmon installer: everything needed for `./fmmon` to run unprivileged.
#
# Installs five things:
#   1. /usr/local/bin/fmmon                      the binary, on PATH
#   2. /usr/local/bin/fmmon-grant-cap           root helper polkit authorises
#   3. net.spoofer.grantcap.policy + 50-fmmon.rules   the polkit policy
#   4. capabilities on xtables-nft-multi and tc, so the iptables and tc children
#      inherit CAP_NET_ADMIN without the GUI running as root
#   5. fmmon.desktop + appicon.png               the launcher entry and its icon
#
# The binary itself needs no capability up front: on first run it asks polkit
# for CAP_NET_RAW and re-execs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/packaging"
BIN_SRC="$SCRIPT_DIR/bin/fmmon"
ICON_SRC="$SCRIPT_DIR/build/appicon.png"

GRANT_CAP=/usr/local/bin/fmmon-grant-cap
POLICY=/usr/share/polkit-1/actions/net.spoofer.grantcap.policy
RULES=/etc/polkit-1/rules.d/50-fmmon.rules
DESKTOP=/usr/share/applications/fmmon.desktop
ICON=/usr/share/icons/hicolor/128x128/apps/fmmon.png
AGENT=/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { printf "${GREEN}[OK]${NC}   %s\n" "$1"; }
warn() { printf "${YELLOW}[!]${NC}   %s\n" "$1"; }
die()  { printf "${RED}[ERR]${NC} %s\n" "$1" >&2; exit 1; }

printf "${CYAN}fmmon installer${NC}\n\n"


# ── 2. Root-requiring steps ──────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "run this with sudo: sudo ./install.sh"

install -m 0755 "$BIN_SRC" /usr/local/bin/fmmon
ok "installed /usr/local/bin/fmmon"

install -m 0755 "$SRC_DIR/fmmon-grant-cap" "$GRANT_CAP"
ok "installed $GRANT_CAP (root-owned, not setuid; pkexec supplies root)"

install -m 0644 "$SRC_DIR/net.spoofer.grantcap.policy" "$POLICY"
ok "installed $POLICY"

install -m 0644 "$SRC_DIR/50-fmmon.rules" "$RULES"
ok "installed $RULES"

# The launcher entry. The Omarchy Apps list is built from the XDG desktop
# entries under /usr/share/applications, so without this file the app is only
# reachable from a terminal. Icon name must match the file installed below.
install -m 0644 "$SRC_DIR/fmmon.desktop" "$DESKTOP"
ok "installed $DESKTOP"

install -d /usr/share/icons/hicolor/128x128/apps
install -m 0644 "$ICON_SRC" "$ICON"
ok "installed $ICON"

if command -v update-desktop-database >/dev/null 2>&1; then
	update-desktop-database -q /usr/share/applications
fi

# iptables and tc are spawned as child processes by the engine. A child of a
# non-root process starts with no capabilities unless it inherits them as
# ambient, and Linux capability sets are per-thread while Go migrates
# goroutines across threads - so ambient cannot work here. Putting
# CAP_NET_ADMIN on the tools themselves is the one approach that holds for every
# exec regardless of which thread forked it.
#
# These are the only parts of the system that keep a privilege after install.
# They are wiped by an iptables/iproute2 package update; rerun this script then.
setcap cap_net_admin=+ep /usr/bin/xtables-nft-multi
setcap cap_net_admin=+ep /usr/bin/tc
ok "granted CAP_NET_ADMIN to xtables-nft-multi and tc"

# ── 3. Polkit agent ──────────────────────────────────────────────────
# Without a running authentication agent polkit has no way to prompt, and
# pkexec fails with "No authentication agent found". The agent may be a
# standalone process (polkit-gnome) or embedded in the desktop shell
# (Omarchy's quickshell registers /org/omarchy/PolkitAgent).
have_agent() {
	pgrep -f authentication-agent >/dev/null 2>&1 && return 0
	journalctl _COMM=quickshell -b --no-pager 2>/dev/null |
		grep 'omarchy polkit agent registered' >/dev/null
}
if have_agent; then
	ok "polkit authentication agent is running"
else
	warn "no polkit authentication agent is running."
	warn "pkexec will fail with 'No authentication agent found' until one runs."
	warn "On Omarchy the agent ships with the shell - restart it with:"
	warn "  omarchy restart shell"
	warn "Otherwise start a standalone agent for this session:"
	warn "  $AGENT &"
fi

systemctl reload polkit 2>/dev/null || systemctl restart polkit 2>/dev/null || true

# ── 4. Verify ────────────────────────────────────────────────────────
printf "\n  Verification\n"
getcap /usr/local/bin/fmmon >/dev/null 2>&1 && \
	printf "    %s\n" "$(getcap /usr/local/bin/fmmon)" || \
	printf "    (fmmon has no caps yet - correct, it requests them on first run)"

command -v fmmon >/dev/null 2>&1 && \
	printf "    fmmon is on PATH\n" || \
	printf "    (fmmon not on PATH - /usr/local/bin missing from PATH)\n"
[[ -f $ICON ]] && printf "    icon: %s\n" "$ICON"
desktop-file-validate "$DESKTOP" >/dev/null 2>&1 || \
	warn "$DESKTOP did not pass desktop-file-validate"

printf "\n${GREEN}Done.${NC} Run:\n\n"
printf "  ${CYAN}fmmon${NC}\n"
printf "  or pick fmmon from the launcher (Super+Space)\n\n"
printf "  The first launch asks for your password once, then re-execs with\n"
printf "  CAP_NET_RAW and opens the window.\n\n"
printf "  After upgrading fmmon, rerun: ${CYAN}sudo ./install.sh${NC}\n"
