# fmmon

A network monitor and traffic shaper.

## Install

```sh
wails3 build
sudo ./install.sh
```

`install.sh` installs the binary, polkit helper, firewall rules, launcher entry, and icon. Run `fmmon` or start it from your app launcher.

## IP forwarding

fmmon needs IPv4 forwarding enabled:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
```

To keep it enabled after a reboot:

```sh
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-fmmon.conf
```

## License

GPL-3.0
