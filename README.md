# ZabTerm

A terminal-based Zabbix alerts monitor built with Textual, providing a three-pane dashboard interface for viewing real-time Zabbix alerts.

## Features

- **Three-pane layout:**
  - Left: Critical/High priority alerts (top) and Info alerts (bottom)
  - Right: Real-time alert details as you navigate
- Real-time monitoring of Zabbix triggers/alerts
- **Alert interaction:**
  - Close alerts with Ctrl-X (acknowledge and mark as closed)
  - Acknowledge alerts with Ctrl-A
  - Add custom messages to alerts with Ctrl-M
  - View acknowledgment history in alert details
- **Desktop notifications** - Get notified when new critical alerts (High/Disaster) appear
  - Uses libnotify (notify-send)
  - Configurable on/off
  - Disaster alerts marked as urgent
- **tmux integration:**
  - Automatic color support detection and configuration
  - Terminal bell signal on new alerts (flags tmux window with activity/attention)
- **Async API calls** - non-blocking UI updates
- **Smart caching** - reduces API load with configurable TTL
  - Triggers cache: 5 second TTL
  - Macros cache: 5 minute TTL
  - Manual refresh (r key) bypasses cache
- Color-coded severity levels (Disaster, High, Average, Warning, etc.)
- Auto-refresh with configurable interval
- Animated spinner showing refresh status
- Filter by severity level
- Show/hide acknowledged alerts
- Statistics bar showing alert counts by severity
- Keyboard shortcuts for navigation and control
- Expanded macros and threshold values
- API key or username/password authentication

## Installation

### Using pipx (recommended)

```bash
pipx install zabterm
```

### Using pip

```bash
pip install zabterm
```

### From source

```bash
git clone https://github.com/yourusername/zabterm.git
cd zabterm
pip install .
```

## Configuration

1. Create configuration file:
```bash
mkdir -p ~/.config/zabterm
cp config.ini.example ~/.config/zabterm/config.ini
```

If you installed via pip/pipx, the example config is included in the package directory.

2. Edit the configuration file with your Zabbix server details:
```ini
[zabbix]
url = https://your-zabbix-server.com

# Use EITHER api_key OR username+password
# api_key = your-api-key-here
username = your-username
password = your-password

verify_ssl = true
refresh_interval = 10

[display]
max_alerts = 100
sort_by = lastchange
show_acknowledged = true
severity_filter = 0
```

## Usage

Run the application:
```bash
zabterm
```

Or specify a custom config file:
```bash
zabterm /path/to/config.ini
```

Run as a module:
```bash
python -m zabterm
```

### Running in tmux

ZabTerm works great in tmux! The application will automatically:
- Detect when running inside tmux
- Configure proper 256-color support for optimal rendering
- Send terminal bell signals when new critical alerts appear, which tmux will detect and flag the window with activity

To enable tmux activity monitoring, add to your `.tmux.conf`:
```
setw -g monitor-bell on
```

This will make tmux highlight the window in the status bar when new alerts appear.

## Keyboard Shortcuts

- `q` - Quit the application
- `r` - Manually refresh data (bypasses cache)
- `Tab` - Switch focus between critical and info tables
- `Ctrl+X` - Close the selected alert (acknowledge with message)
- `Ctrl+A` - Acknowledge the selected alert
- `Ctrl+M` - Add a message to the selected alert
- Arrow keys - Navigate through alerts
- `Ctrl+C` - Force quit

## Configuration Options

### [zabbix] section
- `url`: Zabbix server URL (required)
- `api_key`: API key for authentication (use this OR username+password)
- `username`: Zabbix username (use with password if not using api_key)
- `password`: Zabbix password (use with username if not using api_key)
- `verify_ssl`: Enable/disable SSL verification (true/false)
- `refresh_interval`: Auto-refresh interval in seconds

### [display] section
- `max_alerts`: Maximum number of alerts to display
- `sort_by`: Sort field (lastchange)
- `show_acknowledged`: Show acknowledged alerts (true/false)
- `severity_filter`: Minimum severity level (0-5)
  - 0: Not classified
  - 1: Information
  - 2: Warning
  - 3: Average
  - 4: High
  - 5: Disaster

### [notifications] section
- `enable`: Enable/disable desktop notifications for new critical alerts (true/false)
  - Notifications are sent for High (priority 4) and Disaster (priority 5) alerts only
  - Requires `notify-send` (libnotify) to be installed on your system

## Requirements

- Python 3.8+
- Textual 0.47.0+
- httpx 0.25.0+
- **Optional:** `notify-send` (libnotify) for desktop notifications
  - Install on Debian/Ubuntu: `sudo apt install libnotify-bin`
  - Install on Fedora/RHEL: `sudo dnf install libnotify`
  - Install on Arch: `sudo pacman -S libnotify`
- Requests 2.31.0+
- Zabbix API 5.0+ (should work with most versions)

## License

MIT
