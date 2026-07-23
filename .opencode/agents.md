# Spoofer Agents

## spoofer-core
Deep knowledge of gopacket, ARP spoofing, packet capture/forwarding, MITM traffic counting, rate limiting via token bucket, block/cap enforcement.
- Tools: Read, Edit, Write, Grep, Glob, Bash, WebFetch
- Trigger: tasks involving pkg/arpspoof/, pkg/tracker/, pkg/network/

## spoofer-tui
Specialist in the bubbletea terminal UI for the live tracking display, device selection list, and interactive prompts (cap, rate limit, block).
- Tools: Read, Edit, Write, Grep, Glob, Bash
- Trigger: tasks involving pkg/tracker/display.go, TUI layout, rendering, keybindings

## spoofer-cli
Handles the CLI interface (urfave/cli), subcommand structure, interface picker, gateway auto-detect, and session lifecycle.
- Tools: Read, Edit, Write, Grep, Glob, Bash
- Trigger: tasks involving cmd/spoofer/, CLI flag/arg handling

## spoofer-sys
Low-level OS-specific network operations — both Linux and Windows.
Knows build tags (`//go:build linux`, `//go:build windows`), sysfs, netsh, Win32 API, registry.
- Tools: Read, Edit, Write, Grep, Glob, Bash, WebSearch
- Trigger: tasks involving `*_linux.go`, `*_windows.go` files, platform-specific code

## spoofer-scanner
LAN device discovery via ARP sweep with worker pool, proper subnet iteration, and hostname resolution (reverse DNS).
- Tools: Read, Edit, Write, Grep, Glob, Bash
- Trigger: tasks involving pkg/scanner/

## spoofer-secondary
Implements secondary spoofing features: MAC spoofing, DNS spoofing, IP packet crafting (stubs, not wired into CLI yet).
- Tools: Read, Edit, Write, Grep, Glob, Bash
- Trigger: tasks involving pkg/macspoof/, pkg/dnsspoof/, pkg/ipspoof/
