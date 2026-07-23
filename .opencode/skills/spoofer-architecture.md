# Spoofer Architecture

## Directory Layout
```
spoofer/
├── cmd/spoofer/main.go                     # CLI entry point
├── pkg/
│   ├── network/
│   │   ├── types.go                        # Shared: Device, TrafficCounters, InterfaceInfo
│   │   ├── interface.go                    # Shared: ListInterfaces(), PickDefaultInterface()
│   │   ├── gateway_linux.go                # Gateway from /proc/net/route (little-endian)
│   │   └── gateway_windows.go              # Gateway from Win32 API
│   ├── scanner/
│   │   ├── scan.go                         # Shared: ARP sweep via gopacket (worker pool, multi-octet)
│   │   └── resolve.go                      # Shared: reverse DNS + custom name map
│   ├── arpspoof/
│   │   ├── arp.go                          # Shared: ARP poison, spoof, restore (gopacket)
│   │   ├── table_linux.go                  # arp -d / ip neigh flush
│   │   └── table_windows.go                # arp -d / netsh
│   ├── tracker/
│   │   ├── tracker.go                      # Core: sniff → classify → count → MAC-rewrite → forward
│   │   ├── display.go                      # Bubbletea live TUI
│   │   ├── store.go                        # JSON persistence (~/.spoofer/traffic.json)
│   │   └── capper.go                       # ParseCapSize (KB, MB, GB parser)
│   ├── macspoof/
│   │   ├── mac.go                          # Shared interface (stub)
│   │   ├── mac_linux.go                    # ip link set (stub)
│   │   └── mac_windows.go                  # Registry / SetAdapter (stub)
│   ├── dnsspoof/
│   │   └── dns.go                          # Shared: gopacket DNS response injection (stub)
│   └── ipspoof/
│       └── ip.go                           # Shared: gopacket raw IP packets (stub)
├── go.mod
├── go.sum
└── .opencode/
    ├── agents.md
    └── skills/
        └── spoofer-architecture.md
```

## Core Flow (track command)

```
1. Auto-detect interface (or interactive bubbletea picker if no --iface)
2. Detect gateway IP from default route
3. Create spoofer + tracker (fast, no blocking)
4. Merge saved history from ~/.spoofer/traffic.json
5. Start packet capture goroutine (drops packets until gateway MAC known)
6. Background:
   a. Resolve gateway MAC via ARP (~1s)
   b. Set gateway MAC on tracker (packet processing begins)
   c. ARP scan subnet → discover all live devices (IP + MAC)
   d. Confirm all discovered devices → callback poisons + starts tracking
7. TUI starts immediately showing "Scanning network..."
8. Background completes → TUI transitions to live traffic table
9. Every 30s: periodic ARP rescan for new devices → auto-poison + track
10. On exit: restore all ARP tables, stop packet capture
```

## TUI Screens
- **Interface picker**: Shown at start if `--iface` omitted (bubbletea, j/k/enter)
- **Scanning**: "Scanning network..." while ARP sweep runs
- **Traffic table**: 7 columns (Device, IP, MAC, Rate↓, Rate↑, Total↓, Total↑)
- **Device status**: [B] blocked, [C] capped, [R] rate-limited
- **Prompts**: cap (l), rate limit (r) — inline text input (enter/esc)

## Traffic Handling
- **Classification**: Packets from gateway MAC → counted as DOWN for dst device. Packets from tracked device → counted as UP for src device.
- **Forwarding**: Layer 2 MAC rewrite (no kernel IP forwarding). src MAC → our MAC, dst MAC → real target.
- **Loop prevention**: Skip packets with our own MAC as src (already forwarded).
- **Local device**: Our machine counted as "me". Incoming traffic counted (via gateway poison). Outgoing goes directly to gateway (unpoisoned kernel ARP).

## Rate Limiting
- Token bucket per device (down/up independent)
- `RateLimitDown/RateLimitUp float64` — bytes/sec (0 = unlimited)
- `TokensDown/TokensUp` — available tokens, refilled every packet
- Burst capped at 1 second worth of tokens
- Set via `r` key in TUI (KB/s input, converted to bytes/sec internally)
- Bucket check happens before counting + forwarding; empty bucket → packet dropped

## Bandwidth Caps
- `capDown` / `capUp int64` — total session bytes cap (0 = unlimited)
- When device exceeds cap, all subsequent packets dropped
- Set via `l` key in TUI (MB input, converted to bytes internally)
- Separate from rate limiting: cap is total, rate limit is per-second

## Blocking
- `Blocked bool` per device
- When blocked, all packets to/from device are silently dropped
- Toggle via `b` key in TUI

## Persistence
- JSON file at `~/.spoofer/traffic.json`
- `Save()` on `s` key, `MergeHistory()` on startup
- Stores: IP, MAC, hostname, bytes down/up, packets down/up, last seen

## Scanner
- ARP sweep with worker pool (max 20 concurrent requests)
- Proper multi-octet IP iteration (handles any subnet size)
- Async results channel with non-blocking send, collector goroutine
- 5-second timeout, 30-second periodic rescan

## Key Design Decisions
- **No kernel IP forwarding**: All forwarding at layer 2 via MAC rewrite (like SelfishNet)
- **gopacket for everything**: ARP, sniffing, IP, DNS — same code on both platforms
- **Build tags for OS differences**: `//go:build linux` / `//go:build windows`
- **Async startup**: TUI appears instantly, scanning/poisoning in background
- **Npcap required on Windows**: Same as SelfishNet's WinPcap requirement
- **Mutex-guarded state**: All device access via sync.RWMutex, concurrent-safe
