# Yggdrasil configuration public peers updater

This tool based on [passenger245/yggdrasil-peer-tools](https://github.com/passenger245/yggdrasil-peer-tools) code

Automatically updates public peers in yggdrasil configuration from [`yggdrasil-network/public-peers`](https://github.com/yggdrasil-network/public-peers) repository

# Installation

[Poetry](https://python-poetry.org/) is used for dependency management

```shell
curl -sSL https://install.python-poetry.org | python3 -
```

Create virtual environment and install depencdencies

```shell
make install
```

# Usage

Options:

```
usage: peerupdater.py [-h] [--only-tcp] [--only-tls] [--only-ipv4] [--only-ipv6] [--only-alive] [--sync] [--prefer-tcp] [--prefer-tls] [config_file]

Update yggdrasil configuration file with peers from GitHub repository

positional arguments:
  config_file   Yggdrasil configuration file to update, if not provided, will try to find it automatically in default location    

options:
  -h, --help    show this help message and exit
  --only-tcp    Gather only TCP peers
  --only-tls    Gather only TLS peers
  --only-ipv4   Gather only IPv4 peers
  --only-ipv6   Gather only IPv6 peers
  --only-alive  Add only alive peers to config. Every peers will be checked, it can take some time
  --sync        Sync peers in config with gathered ones. Others words, replaces peers in config with gathered
  --prefer-tcp  If peer is available by TCP and TLS protocols, only TCP will be used
  --prefer-tls  If peer is available by TCP and TLS protocols, only TLS will be used
```

## Examples

```shell
poetry run python peerupdater.py --prefer-tcp --only-ipv4
```

```shell
poetry run python peerupdater.py --sync /etc/yggdrasil/yggdrasil.test.conf
```
