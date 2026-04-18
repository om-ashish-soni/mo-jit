# Example — Debian demo

Fetches a Debian arm64 slim rootfs, boots it under `mojit-run`, and
runs:

```sh
git clone https://github.com/cli/cli.git
apt update && apt install -y htop
go build ./cmd/gh
```

Proves the end-to-end story: network, FS, package manager, compile
toolchain. Lands with M5.
