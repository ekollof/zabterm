#!/usr/bin/env python3
"""Regenerate docs/screenshot.png with fictional demo data.

The app expects a live Zabbix server, so this renders it headlessly with a
stubbed API client. Run from anywhere:

    uv run --with "textual>=8" --with httpx python docs/make_screenshot.py

Rasterizing prefers headless Chromium (best whitespace and font handling) and
falls back to rsvg-convert. ImageMagick is used, when present, to scale the
result down to a reasonable README width.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import zabterm
from zabterm import ZabTerm

OUTPUT = REPO_ROOT / "docs" / "screenshot.png"
WIDTH = 1600
NOW = int(time.time())


def trigger(
    triggerid,
    priority,
    host_name,
    host_id,
    description,
    expression,
    *,
    age=600,
    ack=False,
    opdata="",
    comments="",
    tags=(),
    items=(),
    acknowledges=(),
):
    return {
        "triggerid": triggerid,
        "priority": str(priority),
        "description": description,
        "expression": expression,
        "lastchange": str(NOW - age),
        "comments": comments,
        "hosts": [
            {"hostid": host_id, "host": host_id, "name": host_name, "status": "0"}
        ],
        "lastEvent": [
            {
                "eventid": f"9{triggerid}",
                "clock": str(NOW - age),
                "acknowledged": "1" if ack else "0",
                "opdata": opdata,
            }
        ],
        "items": [
            {"itemid": str(1000 + i), "name": n, "key_": k, "lastvalue": v}
            for i, (n, k, v) in enumerate(items)
        ],
        "tags": [{"tag": t, "value": v} for t, v in tags],
        "_acknowledges": list(acknowledges),
    }


TRIGGERS = [
    trigger(
        "10431",
        5,
        "db-primary.example.com",
        "db-primary",
        "Disk space is critically low on /var (used 97%)",
        "last(/db-primary.example.com/vfs.fs.size[/var,pused])>95",
        age=1820,
        opdata="97 %",
        comments="Free space on {HOST.NAME}: {ITEM.LASTVALUE1}. Check log rotation and old backups.",
        tags=[("service", "database"), ("scope", "capacity")],
        items=[
            (
                "Filesystem /var: Space utilized, in %",
                "vfs.fs.size[/var,pused]",
                "97.42",
            ),
            ("Filesystem /var: Free space", "vfs.fs.size[/var,free]", "3.1 GB"),
        ],
        acknowledges=(
            (
                "2026-11-22 09:14:02",
                "A. Lindqvist",
                "On it — pruning rotated logs and old dumps now.",
            ),
        ),
        ack=True,
    ),
    trigger(
        "10428",
        4,
        "web-03.example.com",
        "web-03",
        "High CPU utilization (over 90% for 5m)",
        "min(/web-03.example.com/system.cpu.util,5m)>90",
        age=540,
        opdata="94.2 %",
        comments="Sustained CPU pressure on {HOST.NAME}.",
        tags=[("service", "web"), ("scope", "performance")],
        items=[
            ("CPU utilization", "system.cpu.util", "94.2"),
            ("Load average (1m)", "system.cpu.load[avg1]", "12.87"),
        ],
    ),
    trigger(
        "10425",
        4,
        "cache-02.example.com",
        "cache-02",
        "MySQL replica lag is over 10 minutes",
        "last(/cache-02.example.com/mysql.slave.lag)>600",
        age=3900,
        opdata="42m 17s",
        comments="Replica {HOST.NAME} is far behind primaries.",
        tags=[("service", "mysql"), ("scope", "replication")],
        items=[("Replication lag", "mysql.slave.lag", "2537")],
    ),
    trigger(
        "10419",
        3,
        "lb-01.example.com",
        "lb-01",
        "Interface eth0: link down",
        "last(/lb-01.example.com/net.if.status[eth0])=2",
        age=760,
        tags=[("service", "network")],
    ),
    trigger(
        "10412",
        2,
        "mail-01.example.com",
        "mail-01",
        "Zabbix agent is not available (for 3m)",
        "nodata(/mail-01.example.com/agent.ping,3m)=1",
        age=2100,
        tags=[("class", "os")],
    ),
    trigger(
        "10407",
        2,
        "web-03.example.com",
        "web-03",
        "Unusual number of 5xx responses on upstream pool",
        "last(/web-03.example.com/web.errors.5xx.rate)>25",
        age=3200,
        opdata="31 req/s",
        tags=[("service", "web")],
    ),
    trigger(
        "10398",
        1,
        "backup-01.example.com",
        "backup-01",
        "Host has been restarted",
        "last(/backup-01.example.com/system.uptime)<600",
        age=450,
        tags=[("class", "os")],
    ),
    trigger(
        "10392",
        1,
        "gw.example.com",
        "gw",
        "TLS certificate expires in 18 days",
        "last(/gw.example.com/web.cert.remaining)<21",
        age=8800,
        opdata="18 d",
        tags=[("service", "tls")],
    ),
    trigger(
        "10385",
        0,
        "ntp-01.example.com",
        "ntp-01",
        "Time drift on NTP peer is above 1s",
        "last(/ntp-01.example.com/ntp.drift)>1000",
        age=12000,
        tags=[("class", "time")],
    ),
]

MACROS = {
    "{$CPU_UTIL_MAX}": "90",
    "{$DISK_USAGE_MAX}": "95",
    "{$MYSQL_REPL_LAG_MAX}": "600",
}

CONFIG = """\
[zabbix]
url = https://zabbix.example.com
api_key = fake-api-key

verify_ssl = true
refresh_interval = 30

[display]
max_alerts = 100
sort_by = lastchange
show_acknowledged = true
severity_filter = 0

[notifications]
enable = false
"""


class FakeZabbix:
    """Stand-in for ZabbixAPI that serves the fixtures above, read-only."""

    def __init__(self, *args, **kwargs):
        pass

    async def login(self):
        return None

    async def get_triggers(self, *args, **kwargs):
        return TRIGGERS

    async def get_user_macros(self, hostids=None):
        return MACROS

    async def get_event_acknowledges(self, eventid):
        for trig in TRIGGERS:
            if str(trig["lastEvent"][0]["eventid"]) == str(eventid):
                return [
                    {
                        "clock": str(
                            int(time.mktime(time.strptime(clock, "%Y-%m-%d %H:%M:%S")))
                        ),
                        "name": user,
                        "message": message,
                    }
                    for clock, user, message in trig.get("_acknowledges", [])
                ]
        return []

    async def _request(self, method, params=None):
        if method == "host.get":
            return [{"hostid": "10101", "parentTemplates": [{"templateid": "20001"}]}]
        return []


async def render_svg(svg_path: Path, config_path: Path) -> None:
    # Keep the default theme so the screenshot does not depend on wallust.
    zabterm.load_wallust_theme = lambda: None
    zabterm.ZabbixAPI = FakeZabbix

    app = ZabTerm(str(config_path))
    async with app.run_test(size=(190, 48)) as pilot:
        # Wait for the initial fetch to populate both tables.
        for _ in range(10):
            await pilot.pause()
        table = app.query_one("#critical-table")
        table.focus()
        table.move_cursor(row=2)  # Show the acknowledged Disaster alert.
        for _ in range(10):
            await pilot.pause()

        app.save_screenshot(str(svg_path))


def view_box(svg: str) -> tuple[int, int]:
    """Return the screenshot's natural pixel size."""
    match = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    if not match:
        raise SystemExit("Unexpected screenshot SVG: no viewBox")
    return (round(float(match.group(1))), round(float(match.group(2))))


def rasterize(svg_path: Path, png_path: Path) -> None:
    svg = svg_path.read_text()
    width, height = view_box(svg)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        html = tmp_dir / "shot.html"
        html.write_text(
            "<!doctype html><html><head><meta charset='utf-8'><style>"
            "html,body{margin:0;padding:0;background:#000}"
            f"svg{{display:block;width:{width}px}}"
            "</style></head><body>"
            f"{svg}</body></html>"
        )

        chromium = shutil.which("chromium") or shutil.which("google-chrome")
        if chromium:
            subprocess.run(
                [
                    chromium,
                    "--headless",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--hide-scrollbars",
                    "--force-device-scale-factor=1",
                    f"--window-size={width},{height}",
                    f"--screenshot={png_path}",
                    str(html),
                ],
                check=True,
                capture_output=True,
            )
        elif shutil.which("rsvg-convert"):
            subprocess.run(
                ["rsvg-convert", "-w", str(WIDTH), str(svg_path), "-o", str(png_path)],
                check=True,
            )
        else:
            raise SystemExit(
                "Need chromium or rsvg-convert to rasterize the screenshot "
                "(ImageMagick is optional, for scaling)"
            )

    if shutil.which("magick"):
        subprocess.run(
            [
                "magick",
                str(png_path),
                "-resize",
                f"{WIDTH}x",
                "-colors",
                "192",
                "-strip",
                str(png_path),
            ],
            check=True,
        )


async def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        config_path = Path(tmp) / "config.ini"
        config_path.write_text(CONFIG)
        svg_path = Path(tmp) / "screenshot.svg"

        await render_svg(svg_path, config_path)
        rasterize(svg_path, OUTPUT)

    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
