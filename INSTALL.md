# Installation Guide

## Quick Start

### Install with pipx (recommended)

```bash
pipx install zabterm
```

### Install with pip

```bash
pip install zabterm
```

## Configuration

1. Create the config directory:
```bash
mkdir -p ~/.config/zabterm
```

2. Create the configuration file at `~/.config/zabterm/config.ini`:
```ini
[zabbix]
url = https://your-zabbix-server.com

# Authentication: Use EITHER api_key OR username+password
api_key = your-api-key-here
# username = your-username
# password = your-password

verify_ssl = true
refresh_interval = 10

[display]
max_alerts = 100
sort_by = lastchange
show_acknowledged = true
severity_filter = 0
```

3. Run zabterm:
```bash
zabterm
```

## Configuration File Locations

ZabTerm searches for configuration files in the following order:

1. `./config.ini` (current directory)
2. `~/.config/zabterm/config.ini` (XDG config directory)
3. `~/.zabterm.ini` (home directory)
4. Custom path: `zabterm /path/to/config.ini`

## Development Installation

```bash
git clone https://github.com/yourusername/zabterm.git
cd zabterm
pip install -e .
```

## Uninstallation

### pipx
```bash
pipx uninstall zabterm
```

### pip
```bash
pip uninstall zabterm
```
