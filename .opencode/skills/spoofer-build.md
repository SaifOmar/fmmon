# Spoofer Build Skill

## Prerequisites
- Go 1.21+
- libpcap-dev (Linux): `sudo apt install libpcap-dev`
- Npcap (Windows): Install from https://npcap.com with "WinPcap API compatibility mode"

## Build
```bash
go build -o spoofer ./cmd/spoofer
# Cross-compile for Windows from Linux:
GOOS=windows GOARCH=amd64 go build -o spoofer.exe ./cmd/spoofer
```

## Test
```bash
go test ./pkg/...
```

## Run (needs root/admin)
```bash
# Linux
sudo ./spoofer track --iface eth0
sudo ./spoofer scan --iface eth0
sudo ./spoofer list

# Windows (admin prompt)
spoofer.exe track --iface "Wi-Fi"
```

## Lint
```bash
golangci-lint run ./...
```

## Dependencies
```bash
go mod tidy
go mod verify
```

## Runtime Error Handling
If pcap initialization fails: "Npcap/WinPcap not installed. Download from https://npcap.com"
