#!/usr/bin/env python3
"""ZabTerm - A Textual-based Zabbix alerts monitor."""

import configparser
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Static, Input, Button
from textual.reactive import reactive
from textual.screen import ModalScreen
from rich.markup import escape


class ZabbixAPI:
    """Simple async Zabbix API client with caching."""

    def __init__(
        self,
        url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.url = url.rstrip("/") + "/api_jsonrpc.php"
        self.username = username
        self.password = password
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.auth_token = None
        self.use_api_key = api_key is not None

        # Cache for user macros (rarely change)
        self._macros_cache = {}
        self._macros_cache_time = {}
        self._macros_cache_ttl = 300  # 5 minutes

        # Cache for trigger data (short-lived)
        self._triggers_cache = None
        self._triggers_cache_time = 0
        self._triggers_cache_ttl = 5  # 5 seconds minimum between fetches

    async def _request(self, method: str, params: Optional[dict] = None) -> Any:
        """Make async API request."""
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1}

        if self.use_api_key:
            headers = {"Authorization": f"Bearer {self.api_key}"}
        else:
            headers = {}
            if self.auth_token and method != "user.login":
                payload["auth"] = self.auth_token

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                response = await client.post(
                    self.url, json=payload, headers=headers, timeout=10.0
                )
                response.raise_for_status()
                result = response.json()

                if "error" in result:
                    raise Exception(f"API Error: {result['error']}")

                return result.get("result")
        except httpx.HTTPError as e:
            raise Exception(f"Connection error: {e}")

    async def login(self):
        """Authenticate with Zabbix."""
        if self.use_api_key:
            return
        self.auth_token = await self._request(
            "user.login", {"username": self.username, "password": self.password}
        )

    async def get_triggers(
        self,
        min_severity: int = 0,
        only_unacknowledged: bool = False,
        force: bool = False,
    ):
        """Get active triggers (alerts) with caching."""
        current_time = time.time()

        # Return cached data if available and not expired
        if not force and self._triggers_cache is not None:
            age = current_time - self._triggers_cache_time
            if age < self._triggers_cache_ttl:
                return self._triggers_cache

        params = {
            "output": "extend",
            "selectHosts": ["hostid", "host", "name", "status"],
            "selectLastEvent": "extend",
            "selectItems": ["itemid", "name", "key_", "lastvalue"],
            "selectFunctions": ["function", "parameter"],
            "selectTags": "extend",
            "filter": {"value": 1},
            "min_severity": min_severity,
            "sortfield": "lastchange",
            "sortorder": "DESC",
            "monitored": True,
            "active": True,
            "skipDependent": True,
            "expandDescription": True,
            "expandName": True,
            "expandExpression": True,
            "expandData": True,
        }

        if only_unacknowledged:
            params["withLastEventUnacknowledged"] = True

        result = await self._request("trigger.get", params)

        # Update cache
        self._triggers_cache = result
        self._triggers_cache_time = current_time

        return result

    async def get_user_macros(self, hostids: Optional[list] = None):
        """Get user macros for hosts and global macros with caching."""
        current_time = time.time()
        cache_key = "global" if not hostids else ",".join(sorted(map(str, hostids)))

        # Check cache
        if cache_key in self._macros_cache:
            age = current_time - self._macros_cache_time.get(cache_key, 0)
            if age < self._macros_cache_ttl:
                return self._macros_cache[cache_key]

        macros = {}

        # Get global macros - always fetch these
        try:
            global_params = {"output": ["macro", "value"], "globalmacro": True}
            global_macros = await self._request("usermacro.get", global_params)
            for m in global_macros:
                macros[m["macro"]] = m["value"]
        except Exception as e:
            pass  # Log in calling code

        # Get host-level macros if hostids provided (these override global)
        if hostids:
            try:
                host_params = {"output": ["macro", "value"], "hostids": hostids}
                host_macros = await self._request("usermacro.get", host_params)
                for m in host_macros:
                    macros[m["macro"]] = m["value"]
            except Exception as e:
                pass  # Log in calling code

        # Update cache
        self._macros_cache[cache_key] = macros
        self._macros_cache_time[cache_key] = current_time

        return macros

    async def acknowledge_event(self, eventid: str, message: str = "Closed via ZabTerm"):
        """Acknowledge and close an event."""
        # action is a bitmask: 1=acknowledge, 2=add message, 4=change severity, etc.
        # To close a problem manually, we acknowledge it (action=1) with a message (action=2)
        # Combined: action=3 (1+2)
        params = {
            "eventids": eventid,
            "action": 3,  # 1 (acknowledge) + 2 (add message)
            "message": message
        }
        return await self._request("event.acknowledge", params)

    async def acknowledge_only(self, eventid: str):
        """Acknowledge an event without closing."""
        params = {
            "eventids": eventid,
            "action": 1,  # 1 = acknowledge only
        }
        return await self._request("event.acknowledge", params)

    async def add_message_to_event(self, eventid: str, message: str):
        """Add a message to an event."""
        params = {
            "eventids": eventid,
            "action": 2,  # 2 = add message
            "message": message
        }
        return await self._request("event.acknowledge", params)

    async def get_event_acknowledges(self, eventid: str):
        """Get acknowledgment history for an event."""
        params = {
            "eventids": eventid,
            "selectAcknowledges": "extend",
            "output": ["eventid"]
        }
        result = await self._request("event.get", params)
        if result and len(result) > 0:
            return result[0].get("acknowledges", [])
        return []


class StatsBar(Static):
    """Display statistics bar."""

    total_alerts = reactive(0)
    critical = reactive(0)
    high = reactive(0)
    average = reactive(0)
    warning = reactive(0)
    refreshing = reactive(False)

    def render(self) -> str:
        spinner = ""
        if self.refreshing:
            import time

            spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            spinner = f" {spinners[int(time.time() * 10) % len(spinners)]}"

        return (
            f"Total: {self.total_alerts} | "
            f"[bold red]Critical: {self.critical}[/] | "
            f"[red]High: {self.high}[/] | "
            f"[yellow]Average: {self.average}[/] | "
            f"[dim yellow]Warning: {self.warning}[/]"
            f"{spinner}"
        )


class DetailScreen(ModalScreen):
    """Screen showing detailed information about an alert."""

    CSS = """
    DetailScreen {
        align: center middle;
    }

    #detail-container {
        width: 80%;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }

    #detail-content {
        height: auto;
        overflow-y: auto;
    }
    """

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("enter", "dismiss", "Close"),
    ]

    def __init__(self, trigger_data: dict, user_macros: Optional[dict] = None):
        super().__init__()
        self.trigger_data = trigger_data
        self.user_macros = user_macros or {}

    def compose(self) -> ComposeResult:
        """Create child widgets."""
        with Container(id="detail-container"):
            yield Static(self._format_details(), id="detail-content")

    def _format_details(self) -> str:
        """Format trigger details for display."""
        trigger = self.trigger_data

        priority_names = {
            0: "Not classified",
            1: "Information",
            2: "Warning",
            3: "Average",
            4: "High",
            5: "Disaster",
        }

        priority = int(trigger.get("priority", 0))
        severity = priority_names.get(priority, "Unknown")

        host_info = trigger.get("hosts", [{}])[0] if trigger.get("hosts") else {}
        host_name = host_info.get("name", "Unknown")
        host_id = host_info.get("host", "Unknown")
        host_status = "Enabled" if host_info.get("status") == "0" else "Disabled"

        last_event = trigger.get("lastEvent", [{}])
        if isinstance(last_event, list):
            last_event = last_event[0] if last_event else {}

        acknowledged = last_event.get("acknowledged", "0") == "1"
        event_id = last_event.get("eventid", "N/A")
        event_time = int(last_event.get("clock", 0))
        event_time_str = (
            datetime.fromtimestamp(event_time).strftime("%Y-%m-%d %H:%M:%S")
            if event_time
            else "N/A"
        )
        event_opdata = last_event.get("opdata", "")

        last_change = int(trigger.get("lastchange", 0))
        last_change_str = datetime.fromtimestamp(last_change).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        duration = int(datetime.now().timestamp()) - last_change
        hours, remainder = divmod(duration, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{hours}h {minutes}m {seconds}s"

        trigger_url = trigger.get("url", "")
        comments = trigger.get("comments", "")
        expression = trigger.get("expression", "N/A")
        error = trigger.get("error", "")
        opdata = event_opdata if event_opdata else trigger.get("opdata", "")

        import re

        # Replace built-in Zabbix macros with actual values
        # Get item values for {ITEM.VALUE} and {ITEM.LASTVALUE} macros
        items = trigger.get("items", [])
        if items:
            item_value = items[0].get("lastvalue", "")
            comments = re.sub(r"\{ITEM\.(?:LAST)?VALUE\d*\}", str(item_value), comments)

        # Replace host macros
        comments = re.sub(r"\{HOST\.NAME\}", host_name, comments)
        comments = re.sub(r"\{HOST\.HOST\}", host_id, comments)

        # Replace event macros
        if opdata and "{" not in opdata:
            comments = re.sub(r"\{EVENT\.OPDATA\}", opdata, comments)

        # Replace user-defined macros
        for macro, value in self.user_macros.items():
            # Handle both regular macros and context-aware macros
            # {$MACRO} or {$MACRO:"context"}
            base_macro = macro.rstrip("}")
            # Pattern matches base macro + optional context + closing brace
            pattern = re.escape(base_macro) + r"(?::[^}]+)?\}"
            comments = re.sub(pattern, value, comments)

        tags = trigger.get("tags", [])
        tags_str = (
            ", ".join([f"{escape(t['tag'])}:{escape(t['value'])}" for t in tags])
            if tags
            else "None"
        )

        items = trigger.get("items", [])
        items_info = []
        current_values = []
        for item in items[:5]:
            item_name = item.get("name", "Unknown")
            last_value = item.get("lastvalue", "N/A")
            items_info.append(
                f"  • {escape(item_name)}\n    Value: {escape(str(last_value))}"
            )
            if "pused" in item.get("key_", "") or "percent" in item_name.lower():
                try:
                    val = float(last_value)
                    current_values.append(f"{val:.1f}%")
                except (ValueError, TypeError):
                    pass
        items_str = "\n".join(items_info) if items_info else "  None"

        current_value_str = ", ".join(current_values) if current_values else None

        details = f"""[bold]Alert Details[/bold]

[bold yellow]═══ Trigger Information ═══[/bold yellow]
[bold cyan]Trigger ID:[/bold cyan] {trigger.get('triggerid', 'N/A')}
[bold cyan]Description:[/bold cyan] {escape(trigger.get('description', 'N/A'))}
[bold cyan]Severity:[/bold cyan] {severity} (Priority: {priority})
[bold cyan]Status:[/bold cyan] PROBLEM
[bold cyan]Duration:[/bold cyan] {duration_str}"""

        if current_value_str:
            details += f"\n[bold cyan]Current Value:[/bold cyan] {current_value_str}"
        elif opdata and "{" not in opdata:
            details += f"\n[bold cyan]Operational Data:[/bold cyan] {escape(opdata)}"

        details += f"\n[bold cyan]Expression:[/bold cyan] {escape(expression)}"

        if error:
            details += f"\n[bold red]Error:[/bold red] {escape(error)}"

        if trigger_url:
            details += f"\n[bold cyan]URL:[/bold cyan] {escape(trigger_url)}"

        if comments:
            details += f"\n\n[bold cyan]Comments:[/bold cyan]\n{escape(comments)}"

        details += f"""

[bold yellow]═══ Host Information ═══[/bold yellow]
[bold cyan]Host Name:[/bold cyan] {escape(host_name)}
[bold cyan]Host ID:[/bold cyan] {host_id}
[bold cyan]Host Status:[/bold cyan] {host_status}

[bold yellow]═══ Event Information ═══[/bold yellow]
[bold cyan]Event ID:[/bold cyan] {event_id}
[bold cyan]Event Time:[/bold cyan] {event_time_str}
[bold cyan]Last Change:[/bold cyan] {last_change_str}
[bold cyan]Acknowledged:[/bold cyan] {'Yes ✓' if acknowledged else 'No ✗'}

[bold yellow]═══ Tags ═══[/bold yellow]
{tags_str}

[bold yellow]═══ Related Items ═══[/bold yellow]
{items_str}

[dim]Press ESC or ENTER to close[/dim]
"""
        return details


class MessageInputScreen(ModalScreen):
    """Screen for entering a message for an alert."""

    CSS = """
    MessageInputScreen {
        align: center middle;
    }

    #message-dialog {
        width: 60;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }

    #message-title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }

    #message-input {
        width: 100%;
        margin-bottom: 1;
    }

    #button-container {
        layout: horizontal;
        height: auto;
        align: center middle;
    }

    Button {
        margin: 0 1;
    }
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(self, prompt: str = "Enter message:"):
        super().__init__()
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        """Create child widgets."""
        with Container(id="message-dialog"):
            yield Static(self.prompt, id="message-title")
            yield Input(placeholder="Type your message here...", id="message-input")
            with Horizontal(id="button-container"):
                yield Button("Submit", variant="primary", id="submit-btn")
                yield Button("Cancel", variant="default", id="cancel-btn")

    def on_mount(self) -> None:
        """Focus the input when mounted."""
        self.query_one("#message-input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "submit-btn":
            message = self.query_one("#message-input", Input).value
            if message.strip():
                self.dismiss(message)
            else:
                self.app.notify("Message cannot be empty", severity="warning")
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input."""
        if event.value.strip():
            self.dismiss(event.value)
        else:
            self.app.notify("Message cannot be empty", severity="warning")

    def action_cancel(self) -> None:
        """Cancel action."""
        self.dismiss(None)


class ZabTerm(App):
    """Textual application for Zabbix monitoring."""

    CSS = """
    Screen {
        background: $surface;
    }

    StatsBar {
        dock: top;
        height: 1;
        background: $boost;
        color: $text;
        padding: 0 1;
    }

    #main-container {
        layout: horizontal;
        height: 100%;
    }

    #left-panel {
        width: 65%;
        layout: vertical;
    }

    #detail-panel {
        width: 35%;
        border: thick $success;
    }

    #detail-title {
        dock: top;
        height: 1;
        background: $success;
        content-align: center middle;
        text-style: bold;
    }

    #detail-content-widget {
        height: 100%;
        overflow-y: auto;
        padding: 1;
    }

    #critical-container {
        height: 60%;
        border: solid $primary;
    }

    #info-container {
        height: 40%;
        border: solid $accent;
    }

    .panel-title {
        dock: top;
        height: 1;
        background: $boost;
        content-align: center middle;
        text-style: bold;
    }

    DataTable {
        height: 100%;
    }

    .severity-0 { color: gray; }
    .severity-1 { color: white; }
    .severity-2 { color: yellow; }
    .severity-3 { color: orange; }
    .severity-4 { color: red; }
    .severity-5 { color: red; text-style: bold; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("tab", "switch_table", "Switch Table"),
        ("ctrl+x", "close_alert", "Close Alert"),
        ("ctrl+a", "ack_alert", "Acknowledge"),
        ("ctrl+m", "message_alert", "Add Message"),
    ]

    def __init__(self, config_path: str = "config.ini"):
        super().__init__()
        self.config = self.load_config(config_path)
        self.zabbix = None
        self.stats_bar = StatsBar()
        self.triggers_cache = {}
        self.known_critical_alerts = set()  # Track critical alert IDs we've seen
        self.initial_load = True  # Flag to skip notifications on first load

    def load_config(self, config_path: str) -> configparser.ConfigParser:
        """Load configuration from INI file."""
        config = configparser.ConfigParser()

        if not Path(config_path).exists():
            self.exit(message=f"Config file not found: {config_path}")

        config.read(config_path)

        if not config.has_option("zabbix", "url"):
            self.exit(message="Missing config: [zabbix] url")

        has_api_key = config.has_option("zabbix", "api_key")
        has_credentials = config.has_option("zabbix", "username") and config.has_option(
            "zabbix", "password"
        )

        if not has_api_key and not has_credentials:
            self.exit(message="Must provide either api_key or username+password")

        return config

    def compose(self) -> ComposeResult:
        """Create child widgets."""
        yield Header()
        yield self.stats_bar
        with Horizontal(id="main-container"):
            with Vertical(id="left-panel"):
                with Vertical(id="critical-container"):
                    yield Static(
                        "🔴 Critical & High Priority Alerts", classes="panel-title"
                    )
                    yield DataTable(id="critical-table")
                with Vertical(id="info-container"):
                    yield Static(
                        "ℹ️  Information & Low Priority Alerts", classes="panel-title"
                    )
                    yield DataTable(id="info-table")
            with Vertical(id="detail-panel"):
                yield Static("📋 Alert Details", id="detail-title")
                yield Static(
                    "Select an alert to view details...", id="detail-content-widget"
                )
        yield Footer()

    def on_mount(self) -> None:
        """Set up the application on mount."""
        critical_table = self.query_one("#critical-table", DataTable)
        info_table = self.query_one("#info-table", DataTable)

        critical_table.cursor_type = "row"
        info_table.cursor_type = "row"

        for table in [critical_table, info_table]:
            table.add_columns(
                "Severity", "Host", "Alert", "Status", "Last Change", "Ack"
            )

        verify_ssl = self.config.getboolean("zabbix", "verify_ssl", fallback=True)
        api_key = self.config.get("zabbix", "api_key", fallback=None)

        if api_key:
            self.zabbix = ZabbixAPI(
                self.config.get("zabbix", "url"), api_key=api_key, verify_ssl=verify_ssl
            )
        else:
            self.zabbix = ZabbixAPI(
                self.config.get("zabbix", "url"),
                username=self.config.get("zabbix", "username"),
                password=self.config.get("zabbix", "password"),
                verify_ssl=verify_ssl,
            )

        # Initial login and data fetch
        self.run_worker(self._async_init(), exclusive=True)

        # Set up periodic refresh
        refresh_interval = self.config.getint(
            "display", "refresh_interval", fallback=10
        )
        self.set_interval(refresh_interval, self.refresh_data)

        # Update spinner animation 10 times per second when refreshing
        self.set_interval(0.1, self._update_spinner)

    async def _async_init(self):
        """Async initialization."""
        try:
            assert self.zabbix is not None
            await self.zabbix.login()
            await self._do_refresh()
        except Exception as e:
            self.notify(f"Error connecting to Zabbix: {e}", severity="error")

    def send_desktop_notification(
        self, title: str, message: str, urgency: str = "normal"
    ) -> None:
        """Send desktop notification using notify-send."""
        try:
            subprocess.run(
                ["notify-send", f"--urgency={urgency}", title, message],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # notify-send not available or timed out, silently ignore
            pass

    def send_terminal_bell(self) -> None:
        """Send a bell signal to the terminal (tmux will flag it with attention)."""
        # Print bell character to stdout - tmux will detect this and flag the window
        sys.stdout.write("\a")
        sys.stdout.flush()

    def _update_spinner(self) -> None:
        """Update spinner animation."""
        if self.stats_bar.refreshing:
            self.stats_bar.refresh()

    def action_refresh(self) -> None:
        """Manual refresh action - bypasses cache."""
        self.refresh_data(force=True)

    def action_switch_table(self) -> None:
        """Switch focus between critical and info tables."""
        critical_table = self.query_one("#critical-table", DataTable)
        info_table = self.query_one("#info-table", DataTable)

        if critical_table.has_focus:
            if info_table.row_count > 0:
                info_table.focus()
                # Update detail pane with info table's current selection
                if info_table.cursor_row is not None and info_table.cursor_row < len(
                    info_table.ordered_rows
                ):
                    row_key = info_table.ordered_rows[info_table.cursor_row].key
                    self.show_detail_in_pane(row_key)
        else:
            if critical_table.row_count > 0:
                critical_table.focus()
                # Update detail pane with critical table's current selection
                if (
                    critical_table.cursor_row is not None
                    and critical_table.cursor_row < len(critical_table.ordered_rows)
                ):
                    row_key = critical_table.ordered_rows[critical_table.cursor_row].key
                    self.show_detail_in_pane(row_key)

    def action_close_alert(self) -> None:
        """Close (acknowledge) the selected alert."""
        # Determine which table has focus
        critical_table = self.query_one("#critical-table", DataTable)
        info_table = self.query_one("#info-table", DataTable)

        active_table = critical_table if critical_table.has_focus else info_table

        # Get the selected row
        if active_table.cursor_row is None or active_table.row_count == 0:
            self.notify("No alert selected", severity="warning")
            return

        if active_table.cursor_row >= len(active_table.ordered_rows):
            self.notify("Invalid selection", severity="warning")
            return

        row_key = active_table.ordered_rows[active_table.cursor_row].key

        if row_key not in self.triggers_cache:
            self.notify("Alert not found in cache", severity="error")
            return

        trigger = self.triggers_cache[row_key]
        
        # Get the event ID from the last event
        last_event = trigger.get("lastEvent", [{}])
        if isinstance(last_event, list):
            last_event = last_event[0] if last_event else {}

        event_id = last_event.get("eventid")
        if not event_id:
            self.notify("No event ID found for this alert", severity="error")
            return

        # Check if already acknowledged
        acknowledged = last_event.get("acknowledged", "0") == "1"
        if acknowledged:
            self.notify("Alert is already acknowledged", severity="info")
            # Still try to close it

        # Close the alert asynchronously
        self.run_worker(self._close_alert_async(event_id, trigger))

    def action_ack_alert(self) -> None:
        """Acknowledge the selected alert."""
        # Determine which table has focus
        critical_table = self.query_one("#critical-table", DataTable)
        info_table = self.query_one("#info-table", DataTable)

        active_table = critical_table if critical_table.has_focus else info_table

        # Get the selected row
        if active_table.cursor_row is None or active_table.row_count == 0:
            self.notify("No alert selected", severity="warning")
            return

        if active_table.cursor_row >= len(active_table.ordered_rows):
            self.notify("Invalid selection", severity="warning")
            return

        row_key = active_table.ordered_rows[active_table.cursor_row].key

        if row_key not in self.triggers_cache:
            self.notify("Alert not found in cache", severity="error")
            return

        trigger = self.triggers_cache[row_key]
        
        # Get the event ID from the last event
        last_event = trigger.get("lastEvent", [{}])
        if isinstance(last_event, list):
            last_event = last_event[0] if last_event else {}

        event_id = last_event.get("eventid")
        if not event_id:
            self.notify("No event ID found for this alert", severity="error")
            return

        # Check if already acknowledged
        acknowledged = last_event.get("acknowledged", "0") == "1"
        if acknowledged:
            self.notify("Alert is already acknowledged", severity="info")
            return

        # Acknowledge the alert asynchronously
        self.run_worker(self._ack_alert_async(event_id, trigger))

    def action_message_alert(self) -> None:
        """Add a message to the selected alert."""
        # Determine which table has focus
        critical_table = self.query_one("#critical-table", DataTable)
        info_table = self.query_one("#info-table", DataTable)

        active_table = critical_table if critical_table.has_focus else info_table

        # Get the selected row
        if active_table.cursor_row is None or active_table.row_count == 0:
            self.notify("No alert selected", severity="warning")
            return

        if active_table.cursor_row >= len(active_table.ordered_rows):
            self.notify("Invalid selection", severity="warning")
            return

        row_key = active_table.ordered_rows[active_table.cursor_row].key

        if row_key not in self.triggers_cache:
            self.notify("Alert not found in cache", severity="error")
            return

        trigger = self.triggers_cache[row_key]
        
        # Get the event ID from the last event
        last_event = trigger.get("lastEvent", [{}])
        if isinstance(last_event, list):
            last_event = last_event[0] if last_event else {}

        event_id = last_event.get("eventid")
        if not event_id:
            self.notify("No event ID found for this alert", severity="error")
            return

        # Show message input screen
        def handle_message(message: Optional[str]) -> None:
            if message:
                self.run_worker(self._add_message_async(event_id, message, trigger))

        self.push_screen(MessageInputScreen("Add message to alert:"), handle_message)

    def refresh_data(self, force: bool = False) -> None:
        """Trigger async data refresh."""
        self.run_worker(self._do_refresh(force=force), exclusive=True)

    async def _close_alert_async(self, event_id: str, trigger: dict) -> None:
        """Async method to close an alert."""
        try:
            host_name = (
                trigger["hosts"][0]["name"] if trigger.get("hosts") else "Unknown"
            )
            description = trigger.get("description", "Unknown")

            assert self.zabbix is not None
            await self.zabbix.acknowledge_event(event_id)

            # Escape markup characters in the notification message
            self.notify(f"Closed alert: {escape(host_name)} - {escape(description)}", severity="information")

            # Refresh data to update the display
            await self._do_refresh(force=True)

        except Exception as e:
            self.notify(f"Failed to close alert: {escape(str(e))}", severity="error")

    async def _ack_alert_async(self, event_id: str, trigger: dict) -> None:
        """Async method to acknowledge an alert."""
        try:
            host_name = (
                trigger["hosts"][0]["name"] if trigger.get("hosts") else "Unknown"
            )
            description = trigger.get("description", "Unknown")

            assert self.zabbix is not None
            await self.zabbix.acknowledge_only(event_id)

            self.notify(f"Acknowledged: {escape(host_name)} - {escape(description)}", severity="information")

            # Refresh data to update the display
            await self._do_refresh(force=True)

        except Exception as e:
            self.notify(f"Failed to acknowledge alert: {escape(str(e))}", severity="error")

    async def _add_message_async(self, event_id: str, message: str, trigger: dict) -> None:
        """Async method to add a message to an alert."""
        try:
            host_name = (
                trigger["hosts"][0]["name"] if trigger.get("hosts") else "Unknown"
            )
            description = trigger.get("description", "Unknown")

            assert self.zabbix is not None
            await self.zabbix.add_message_to_event(event_id, message)

            self.notify(f"Message added to: {escape(host_name)} - {escape(description)}", severity="information")

            # Refresh data to update the display
            await self._do_refresh(force=True)

        except Exception as e:
            self.notify(f"Failed to add message: {escape(str(e))}", severity="error")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection - update detail pane."""
        self.show_detail_in_pane(event.row_key)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Handle row highlight - update detail pane as cursor moves."""
        # Only update if the event is from the currently focused table
        if event.row_key and event.data_table.has_focus:
            self.show_detail_in_pane(event.row_key)

    def show_detail_in_pane(self, row_key) -> None:
        """Update the detail pane with trigger information."""
        if row_key not in self.triggers_cache:
            return

        trigger = self.triggers_cache[row_key]

        # Fetch macros async
        self.run_worker(self._fetch_and_show_details(trigger))

    async def _fetch_and_show_details(self, trigger: dict) -> None:
        """Fetch macros and update detail pane."""
        hosts = trigger.get("hosts", [])
        hostids = [host["hostid"] for host in hosts]
        user_macros = {}
        acknowledges = []
        
        try:
            assert self.zabbix is not None
            # Get global and host-level macros
            user_macros = await self.zabbix.get_user_macros(hostids)
            
            # Also get template-level macros for the hosts
            if hostids:
                host_data = await self.zabbix._request("host.get", {
                    "output": ["hostid"],
                    "hostids": hostids,
                    "selectParentTemplates": ["templateid"]
                })
                
                if host_data and host_data[0].get("parentTemplates"):
                    template_ids = [t["templateid"] for t in host_data[0]["parentTemplates"]]
                    if template_ids:
                        # Fetch macros from templates - templates are stored as hostids
                        template_macros = await self.zabbix._request("usermacro.get", {
                            "output": ["macro", "value"],
                            "hostids": template_ids  # Use hostids for templates
                        })
                        # Add template macros (host/global macros take precedence)
                        for m in template_macros:
                            if m["macro"] not in user_macros:
                                user_macros[m["macro"]] = m["value"]
            
            # Get event acknowledgments
            last_event = trigger.get("lastEvent", [{}])
            if isinstance(last_event, list):
                last_event = last_event[0] if last_event else {}
            event_id = last_event.get("eventid")
            if event_id:
                acknowledges = await self.zabbix.get_event_acknowledges(event_id)
                
        except Exception as e:
            self.log(f"Error fetching macros: {e}")

        detail_widget = self.query_one("#detail-content-widget", Static)
        detail_widget.update(self._format_trigger_details(trigger, user_macros, acknowledges))

    def _format_trigger_details(self, trigger: dict, user_macros: dict, acknowledges: list = None) -> str:
        """Format trigger details for display."""
        if acknowledges is None:
            acknowledges = []
            
        priority_names = {
            0: "Not classified",
            1: "Information",
            2: "Warning",
            3: "Average",
            4: "High",
            5: "Disaster",
        }

        priority = int(trigger.get("priority", 0))
        severity = priority_names.get(priority, "Unknown")

        host_info = trigger.get("hosts", [{}])[0] if trigger.get("hosts") else {}
        host_name = host_info.get("name", "Unknown")
        host_id = host_info.get("host", "Unknown")
        host_status = "Enabled" if host_info.get("status") == "0" else "Disabled"

        last_event = trigger.get("lastEvent", [{}])
        if isinstance(last_event, list):
            last_event = last_event[0] if last_event else {}

        acknowledged = last_event.get("acknowledged", "0") == "1"
        event_id = last_event.get("eventid", "N/A")
        event_time = int(last_event.get("clock", 0))
        event_time_str = (
            datetime.fromtimestamp(event_time).strftime("%Y-%m-%d %H:%M:%S")
            if event_time
            else "N/A"
        )

        last_change = int(trigger.get("lastchange", 0))
        last_change_str = datetime.fromtimestamp(last_change).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        duration = int(datetime.now().timestamp()) - last_change
        hours, remainder = divmod(duration, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{hours}h {minutes}m {seconds}s"

        trigger_url = trigger.get("url", "")
        comments = trigger.get("comments", "")
        expression = trigger.get("expression", "N/A")
        error = trigger.get("error", "")

        import re

        # Get items early for macro replacement
        items = trigger.get("items", [])

        # Replace built-in Zabbix macros with actual values
        if items:
            item_value = items[0].get("lastvalue", "")
            comments = re.sub(r"\{ITEM\.(?:LAST)?VALUE\d*\}", str(item_value), comments)

        # Replace host macros
        comments = re.sub(r"\{HOST\.NAME\}", host_name, comments)
        comments = re.sub(r"\{HOST\.HOST\}", host_id, comments)

        # Replace event macros
        event_opdata = last_event.get("opdata", "")
        if event_opdata and "{" not in event_opdata:
            comments = re.sub(r"\{EVENT\.OPDATA\}", event_opdata, comments)

        # Replace user-defined macros
        for macro, value in user_macros.items():
            # Handle both {$MACRO} and {$MACRO:"context"} formats
            # Escape the full macro and create a pattern that matches with optional context
            if macro.endswith("}"):
                base_macro = macro[:-1]  # Remove the closing brace
                pattern = re.escape(base_macro) + r"(?::[^}]+)?\}"
                # Escape backslashes in value to prevent regex interpretation
                escaped_value = value.replace("\\", "\\\\")
                comments = re.sub(pattern, escaped_value, comments)
            else:
                # If macro doesn't end with }, just do a direct replacement
                escaped_value = value.replace("\\", "\\\\")
                comments = re.sub(re.escape(macro), escaped_value, comments)

        tags = trigger.get("tags", [])
        tags_str = (
            ", ".join([f"{escape(t['tag'])}:{escape(t['value'])}" for t in tags])
            if tags
            else "None"
        )

        items_info = []
        current_values = []
        for item in items[:3]:
            item_name = item.get("name", "Unknown")
            last_value = item.get("lastvalue", "N/A")
            items_info.append(f"  • {escape(item_name)}: {escape(str(last_value))}")
            if "pused" in item.get("key_", "") or "percent" in item_name.lower():
                try:
                    val = float(last_value)
                    current_values.append(f"{val:.1f}%")
                except (ValueError, TypeError):
                    pass
        items_str = "\n".join(items_info) if items_info else "  None"

        current_value_str = ", ".join(current_values) if current_values else None

        details = f"""[bold yellow]Trigger Information[/bold yellow]

[cyan]ID:[/cyan] {trigger.get('triggerid', 'N/A')}
[cyan]Description:[/cyan]
{escape(trigger.get('description', 'N/A'))}

[cyan]Severity:[/cyan] {severity}
[cyan]Duration:[/cyan] {duration_str}"""

        if current_value_str:
            details += f"\n[cyan]Current:[/cyan] {current_value_str}"

        details += f"""

[bold yellow]Host Information[/bold yellow]
[cyan]Name:[/cyan] {escape(host_name)}
[cyan]ID:[/cyan] {host_id}
[cyan]Status:[/cyan] {host_status}

[bold yellow]Event Information[/bold yellow]
[cyan]Event ID:[/cyan] {event_id}
[cyan]Time:[/cyan] {event_time_str}
[cyan]Last Change:[/cyan] {last_change_str}
[cyan]Ack:[/cyan] {'Yes ✓' if acknowledged else 'No ✗'}

[bold yellow]Expression[/bold yellow]
{escape(expression)}"""

        if error:
            details += f"\n\n[bold red]Error:[/bold red]\n{escape(error)}"

        if trigger_url:
            details += f"\n\n[cyan]URL:[/cyan] {escape(trigger_url)}"

        if comments:
            details += f"\n\n[bold yellow]Comments[/bold yellow]\n{escape(comments)}"

        if tags_str != "None":
            details += f"\n\n[bold yellow]Tags[/bold yellow]\n{tags_str}"

        if acknowledges:
            details += "\n\n[bold yellow]Acknowledgments[/bold yellow]"
            for ack in acknowledges:
                ack_time = int(ack.get("clock", 0))
                ack_time_str = datetime.fromtimestamp(ack_time).strftime("%Y-%m-%d %H:%M:%S") if ack_time else "N/A"
                ack_user = ack.get("name", "Unknown")
                ack_message = ack.get("message", "")
                ack_action = int(ack.get("action", 0))
                
                # Decode action flags
                action_parts = []
                if ack_action & 1:
                    action_parts.append("Acknowledged")
                if ack_action & 4:
                    action_parts.append("Severity changed")
                if ack_action & 8:
                    action_parts.append("Unacknowledged")
                if ack_action & 16:
                    action_parts.append("Suppressed")
                if ack_action & 32:
                    action_parts.append("Unsuppressed")
                
                action_str = ", ".join(action_parts) if action_parts else ""
                
                # Build the acknowledgment line
                details += f"\n  • [{ack_time_str}] {escape(ack_user)}"
                if action_str:
                    details += f" - {action_str}"
                
                # Always show message if present (on same line for short messages, new line for longer ones)
                if ack_message:
                    if len(ack_message) < 60 and "\n" not in ack_message:
                        details += f": {escape(ack_message)}"
                    else:
                        details += f"\n    [dim]→[/dim] {escape(ack_message)}"

        if items_info:
            details += f"\n\n[bold yellow]Items[/bold yellow]\n{items_str}"

        return details

    async def _do_refresh(self, force: bool = False) -> None:
        """Async data refresh."""
        self.stats_bar.refreshing = True

        critical_table = self.query_one("#critical-table", DataTable)
        info_table = self.query_one("#info-table", DataTable)

        # Save which table has focus by ID and which alert is selected
        focused_table_id = None
        selected_trigger_id = None
        
        if self.focused is not None:
            focused_table_id = self.focused.id
        
        # Get the currently selected trigger ID
        if critical_table.has_focus and critical_table.cursor_row is not None and critical_table.row_count > 0:
            if critical_table.cursor_row < len(critical_table.ordered_rows):
                selected_trigger_id = critical_table.ordered_rows[critical_table.cursor_row].key
        elif info_table.has_focus and info_table.cursor_row is not None and info_table.row_count > 0:
            if info_table.cursor_row < len(info_table.ordered_rows):
                selected_trigger_id = info_table.ordered_rows[info_table.cursor_row].key
        
        critical_cursor_row = critical_table.cursor_row
        info_cursor_row = info_table.cursor_row

        try:
            min_severity = self.config.getint("display", "severity_filter", fallback=0)
            show_ack = self.config.getboolean(
                "display", "show_acknowledged", fallback=True
            )

            assert self.zabbix is not None
            triggers = await self.zabbix.get_triggers(
                min_severity=min_severity, only_unacknowledged=not show_ack, force=force
            )

            critical_table.clear()
            info_table.clear()
            # Don't clear triggers_cache yet - we need it for the detail pane
            new_triggers_cache = {}

            severity_names = {
                0: ("Not classified", "gray"),
                1: ("Information", "white"),
                2: ("Warning", "yellow"),
                3: ("Average", "orange"),
                4: ("High", "red"),
                5: ("Disaster", "bold red"),
            }

            severity_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0}

            # Separate triggers into critical/high and info/low
            critical_triggers = []
            info_triggers = []

            for trigger in triggers:
                priority = int(trigger["priority"])
                severity_counts[priority] += 1

                # Priority 2-5: Warning, Average, High, Disaster -> Critical pane
                # Priority 0-1: Not classified, Information -> Info pane
                if priority >= 2:
                    critical_triggers.append(trigger)
                else:
                    info_triggers.append(trigger)

            # Sort by lastchange (most recent first)
            critical_triggers.sort(
                key=lambda t: int(t.get("lastchange", 0)), reverse=True
            )
            info_triggers.sort(key=lambda t: int(t.get("lastchange", 0)), reverse=True)

            # Check for new critical alerts (priority 4-5: High and Disaster)
            current_critical_ids = {
                t["triggerid"] for t in triggers if int(t["priority"]) >= 4
            }
            new_critical_alerts = current_critical_ids - self.known_critical_alerts

            # Send notifications for new critical alerts
            # Skip on initial load to avoid spam - only notify on alerts that appear after startup
            notifications_enabled = self.config.getboolean(
                "notifications", "enable", fallback=True
            )
            if notifications_enabled and new_critical_alerts and not self.initial_load:
                # Send terminal bell to flag tmux window with activity/attention
                self.send_terminal_bell()

                for trigger_id in new_critical_alerts:
                    trigger = next(
                        (t for t in triggers if t["triggerid"] == trigger_id), None
                    )
                    if trigger:
                        priority = int(trigger["priority"])
                        host_name = (
                            trigger["hosts"][0]["name"]
                            if trigger["hosts"]
                            else "Unknown"
                        )
                        description = trigger["description"]

                        severity_names_notify = {4: "High", 5: "Disaster"}
                        severity = severity_names_notify.get(priority, "Critical")
                        urgency = "critical" if priority == 5 else "normal"

                        self.send_desktop_notification(
                            f"Zabbix Alert: {severity}",
                            f"{host_name}: {description}",
                            urgency=urgency,
                        )

            # Update known critical alerts and mark initial load as complete
            self.known_critical_alerts = current_critical_ids
            self.initial_load = False

            # Populate critical table
            for trigger in critical_triggers:
                priority = int(trigger["priority"])
                trigger_id = trigger["triggerid"]
                new_triggers_cache[trigger_id] = trigger

                sev_name, sev_color = severity_names.get(priority, ("Unknown", "white"))

                host_name = (
                    trigger["hosts"][0]["name"] if trigger["hosts"] else "Unknown"
                )
                description = trigger["description"]

                # Truncate description to fit on screen
                max_desc_length = 60
                if len(description) > max_desc_length:
                    description = description[: max_desc_length - 3] + "..."

                last_event = trigger.get("lastEvent", [{}])
                if isinstance(last_event, list):
                    last_event = last_event[0] if last_event else {}

                acknowledged = last_event.get("acknowledged", "0") == "1"
                ack_status = "✓" if acknowledged else "✗"

                last_change = int(trigger.get("lastchange", 0))
                time_str = datetime.fromtimestamp(last_change).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                critical_table.add_row(
                    f"[{sev_color}]{sev_name}[/]",
                    escape(host_name),
                    escape(description),
                    "PROBLEM",
                    time_str,
                    ack_status,
                    key=trigger_id,
                )

            # Populate info table
            for trigger in info_triggers:
                priority = int(trigger["priority"])
                trigger_id = trigger["triggerid"]
                new_triggers_cache[trigger_id] = trigger

                sev_name, sev_color = severity_names.get(priority, ("Unknown", "white"))

                host_name = (
                    trigger["hosts"][0]["name"] if trigger["hosts"] else "Unknown"
                )
                description = trigger["description"]

                # Truncate description to fit on screen
                max_desc_length = 60
                if len(description) > max_desc_length:
                    description = description[: max_desc_length - 3] + "..."

                last_event = trigger.get("lastEvent", [{}])
                if isinstance(last_event, list):
                    last_event = last_event[0] if last_event else {}

                acknowledged = last_event.get("acknowledged", "0") == "1"
                ack_status = "✓" if acknowledged else "✗"

                last_change = int(trigger.get("lastchange", 0))
                time_str = datetime.fromtimestamp(last_change).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                info_table.add_row(
                    f"[{sev_color}]{sev_name}[/]",
                    escape(host_name),
                    escape(description),
                    "PROBLEM",
                    time_str,
                    ack_status,
                    key=trigger_id,
                )

            # Now update the triggers cache after all rows are added
            self.triggers_cache = new_triggers_cache

            # Restore cursor positions - try to find the previously selected trigger first
            cursor_restored = False
            restored_in_critical = False
            restored_in_info = False
            
            if selected_trigger_id is not None:
                # Try to find the trigger in the critical table first
                for idx, row in enumerate(critical_table.ordered_rows):
                    if row.key == selected_trigger_id:
                        critical_table.move_cursor(row=idx)
                        restored_in_critical = True
                        cursor_restored = True
                        break
                
                # If not in critical, try info table
                if not cursor_restored:
                    for idx, row in enumerate(info_table.ordered_rows):
                        if row.key == selected_trigger_id:
                            info_table.move_cursor(row=idx)
                            restored_in_info = True
                            cursor_restored = True
                            break
            
            # If we couldn't restore to the same trigger, use the old cursor position
            if not cursor_restored:
                if critical_cursor_row is not None and critical_table.row_count > 0:
                    critical_table.move_cursor(
                        row=min(critical_cursor_row, critical_table.row_count - 1)
                    )

                if info_cursor_row is not None and info_table.row_count > 0:
                    info_table.move_cursor(
                        row=min(info_cursor_row, info_table.row_count - 1)
                    )

            # Restore focus to the table that had it before refresh
            if focused_table_id is not None:
                if (
                    focused_table_id == "critical-table"
                    and critical_table.row_count > 0
                ):
                    critical_table.focus()
                    # Only update detail pane if cursor is valid
                    if (
                        critical_table.cursor_row is not None
                        and critical_table.cursor_row < len(critical_table.ordered_rows)
                    ):
                        row_key = critical_table.ordered_rows[
                            critical_table.cursor_row
                        ].key
                        # Only update if we restored to the same trigger or it changed
                        if cursor_restored and selected_trigger_id == row_key:
                            # Same trigger, just refresh details
                            self.show_detail_in_pane(row_key)
                        elif not cursor_restored:
                            # Different trigger, update details
                            self.show_detail_in_pane(row_key)
                elif focused_table_id == "info-table" and info_table.row_count > 0:
                    info_table.focus()
                    # Only update detail pane if cursor is valid
                    if (
                        info_table.cursor_row is not None
                        and info_table.cursor_row < len(info_table.ordered_rows)
                    ):
                        row_key = info_table.ordered_rows[info_table.cursor_row].key
                        # Only update if we restored to the same trigger or it changed
                        if cursor_restored and selected_trigger_id == row_key:
                            # Same trigger, just refresh details
                            self.show_detail_in_pane(row_key)
                        elif not cursor_restored:
                            # Different trigger, update details
                            self.show_detail_in_pane(row_key)

            self.stats_bar.total_alerts = len(triggers)
            self.stats_bar.critical = severity_counts[5]
            self.stats_bar.high = severity_counts[4]
            self.stats_bar.average = severity_counts[3]
            self.stats_bar.warning = severity_counts[2]
            self.stats_bar.refreshing = False

            # Calculate cache age
            assert self.zabbix is not None
            cache_age = time.time() - self.zabbix._triggers_cache_time
            cache_indicator = " [cached]" if cache_age < 1 else ""

            self.sub_title = (
                f"Last update: {datetime.now().strftime('%H:%M:%S')}{cache_indicator}"
            )

        except Exception as e:
            self.stats_bar.refreshing = False
            self.notify(f"Error fetching data: {e}", severity="error")


def main():
    """Entry point."""
    import os
    import argparse

    # Fix tmux rendering issues by ensuring proper color support
    if os.environ.get("TMUX"):
        # We're running inside tmux
        # Force 256 color support if not already set
        if "TERM" in os.environ and "256color" not in os.environ["TERM"]:
            # Try to use screen-256color or tmux-256color
            if "screen" in os.environ["TERM"]:
                os.environ["TERM"] = "screen-256color"
            elif "tmux" in os.environ["TERM"]:
                os.environ["TERM"] = "tmux-256color"
            else:
                os.environ["TERM"] = "xterm-256color"

    parser = argparse.ArgumentParser(
        description="ZabTerm - Terminal-based Zabbix alerts monitor",
        epilog="Config file is searched in: ./config.ini, ~/.config/zabterm/config.ini, ~/.zabterm.ini",
    )
    parser.add_argument(
        "config",
        nargs="?",
        help="Path to config file (optional if config exists in standard location)",
    )
    parser.add_argument("--version", action="version", version="zabterm 1.0.0")

    args = parser.parse_args()

    # Look for config in multiple locations
    if args.config:
        config_file = args.config
    else:
        config_locations = [
            "config.ini",  # Current directory
            os.path.expanduser("~/.config/zabterm/config.ini"),  # XDG config
            os.path.expanduser("~/.zabterm.ini"),  # Home directory
            os.path.join(os.path.dirname(__file__), "config.ini"),  # Package directory
        ]

        config_file = None
        for location in config_locations:
            if os.path.exists(location):
                config_file = location
                break

        if not config_file:
            print("Error: No config file found. Please create one at:")
            print("  ~/.config/zabterm/config.ini")
            print("or provide path as argument: zabterm /path/to/config.ini")
            print("\nExample config (config.ini.example) can be found in the zabterm source directory.")
            sys.exit(1)

    app = ZabTerm(config_path=config_file)
    app.run()


if __name__ == "__main__":
    main()
