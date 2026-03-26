#!/usr/bin/env python3
"""
Honeypot Framework
==================
Simulates SSH, FTP, HTTP, and Telnet services to lure and fingerprint
attackers. Logs all credentials, commands, and connection metadata.
Uses asyncio for high-concurrency listener management.

Author: Egwu Donatus Achema
Usage:
    sudo python3 honeypot.py --ssh 2222 --ftp 2121 --http 8080 --telnet 2323
    sudo python3 honeypot.py --all --log-dir /var/log/honeypot
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import random
import re
import signal
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# Optional GeoIP (install with: pip install geoip2)
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
class AttackerLog:
    """Central event logger — writes to JSONL and SQLite."""

    def __init__(self, log_dir: str = "honeypot_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._file = open(self.log_dir / "events.jsonl", "a")

    def record(self, service: str, src_ip: str, src_port: int, event_type: str, data: dict):
        entry = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "service": service,
            "src_ip": src_ip,
            "src_port": src_port,
            "event_type": event_type,
            **data,
        }
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()
        log.info(f"[{service}] {src_ip}:{src_port} — {event_type}: {json.dumps(data)[:120]}")

    def close(self):
        self._file.close()


# ══════════════════════════════════════════════════════════════════════════════
class GeoLocator:
    """Optional IP geolocation using MaxMind GeoLite2."""

    def __init__(self, db_path: str = "GeoLite2-City.mmdb"):
        self.reader = None
        if GEOIP_AVAILABLE and Path(db_path).exists():
            import geoip2.database
            self.reader = geoip2.database.Reader(db_path)

    def lookup(self, ip: str) -> dict:
        if not self.reader:
            return {}
        try:
            r = self.reader.city(ip)
            return {
                "country": r.country.name,
                "city": r.city.name,
                "lat": r.location.latitude,
                "lon": r.location.longitude,
                "isp": getattr(r.traits, "isp", ""),
            }
        except Exception:
            return {}


GEOLOCATOR = GeoLocator()


# ══════════════════════════════════════════════════════════════════════════════
#  SSH Honeypot
# ══════════════════════════════════════════════════════════════════════════════
class SSHHoneypot:
    """
    Fake SSH server — accepts connections, captures credentials,
    presents a fake shell, and logs all commands.
    Uses raw asyncio TCP (no paramiko dependency required for skeleton).
    """

    BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    FAKE_PROMPT = b"user@ubuntu:~$ "

    # Fake file system responses
    FAKE_RESPONSES = {
        "ls": "Desktop  Documents  Downloads  Music  Pictures\r\n",
        "pwd": "/home/user\r\n",
        "whoami": "user\r\n",
        "id": "uid=1000(user) gid=1000(user) groups=1000(user),4(adm)\r\n",
        "uname -a": "Linux ubuntu 5.15.0-76-generic #83-Ubuntu SMP x86_64 GNU/Linux\r\n",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
        "ifconfig": "eth0: flags=4163  mtu 1500\n  inet 192.168.1.100\n",
        "uptime": " 14:32:01 up 3 days,  2:15,  1 user,  load average: 0.01, 0.02, 0.00\r\n",
        "history": "  1  ls\n  2  cd /\n  3  cat /etc/passwd\n",
    }

    def __init__(self, port: int, attacker_log: AttackerLog):
        self.port = port
        self.logger = attacker_log

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        src_ip, src_port = peer[0], peer[1]
        geo = GEOLOCATOR.lookup(src_ip)

        self.logger.record("SSH", src_ip, src_port, "CONNECTION", {"geo": geo})

        try:
            # Send SSH banner
            writer.write(self.BANNER)
            await writer.drain()

            # Simulate SSH handshake (simplified — capture raw auth attempts)
            # Real SSH honeypots use paramiko; this captures banner grabbers + scripts
            data = await asyncio.wait_for(reader.read(512), timeout=30)

            # Try to parse any plaintext credentials from scripts
            raw = data.decode(errors="replace")
            self.logger.record("SSH", src_ip, src_port, "HANDSHAKE_DATA", {"raw_hex": data.hex()[:200], "text": raw[:100]})

            # Simulate auth failure → success (lure attacker in)
            await asyncio.sleep(1.5)

            # Fake interactive shell
            writer.write(b"\r\nWelcome to Ubuntu 20.04.5 LTS\r\n")
            writer.write(b"Last login: Mon Dec 11 09:14:32 2023 from 192.168.1.1\r\n\r\n")
            writer.write(self.FAKE_PROMPT)
            await writer.drain()

            # Read and respond to commands
            async for line in self._read_lines(reader):
                cmd = line.strip()
                if not cmd:
                    writer.write(self.FAKE_PROMPT)
                    await writer.drain()
                    continue
                self.logger.record("SSH", src_ip, src_port, "COMMAND", {"cmd": cmd})

                # Exit
                if cmd in ("exit", "quit", "logout"):
                    writer.write(b"logout\r\n")
                    await writer.drain()
                    break

                response = self.FAKE_RESPONSES.get(cmd, f"-bash: {cmd}: command not found\r\n")
                writer.write(response.encode())
                writer.write(self.FAKE_PROMPT)
                await writer.drain()
                await asyncio.sleep(random.uniform(0.05, 0.3))

        except (asyncio.TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            log.debug(f"SSH handler error: {e}")
        finally:
            self.logger.record("SSH", src_ip, src_port, "DISCONNECT", {})
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_lines(self, reader: asyncio.StreamReader):
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=300)
                if not line:
                    break
                yield line.decode(errors="replace")
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                break

    async def start(self):
        server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.port)
        log.info(f"🍯 SSH honeypot listening on :{self.port}")
        async with server:
            await server.serve_forever()


# ══════════════════════════════════════════════════════════════════════════════
#  FTP Honeypot
# ══════════════════════════════════════════════════════════════════════════════
class FTPHoneypot:
    """Fake FTP server that captures credential attempts."""

    BANNER = b"220 FTP Server Ready\r\n"

    def __init__(self, port: int, attacker_log: AttackerLog):
        self.port = port
        self.logger = attacker_log

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        src_ip, src_port = peer[0], peer[1]
        self.logger.record("FTP", src_ip, src_port, "CONNECTION", {})
        username = None

        try:
            writer.write(self.BANNER)
            await writer.drain()

            async for line in self._read_lines(reader):
                cmd = line.strip().upper()

                if cmd.startswith("USER"):
                    username = line.strip()[5:]
                    writer.write(b"331 Password required\r\n")

                elif cmd.startswith("PASS"):
                    password = line.strip()[5:]
                    self.logger.record("FTP", src_ip, src_port, "AUTH_ATTEMPT", {
                        "username": username, "password": password
                    })
                    # Always deny
                    writer.write(b"530 Login incorrect.\r\n")
                    username = None

                elif cmd in ("QUIT", "EXIT"):
                    writer.write(b"221 Goodbye.\r\n")
                    break

                elif cmd.startswith("FEAT"):
                    writer.write(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")

                else:
                    writer.write(b"502 Command not implemented.\r\n")

                await writer.drain()

        except Exception:
            pass
        finally:
            self.logger.record("FTP", src_ip, src_port, "DISCONNECT", {})
            try:
                writer.close()
            except Exception:
                pass

    async def _read_lines(self, reader):
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=60)
                if not line:
                    break
                yield line.decode(errors="replace")
            except Exception:
                break

    async def start(self):
        server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.port)
        log.info(f"🍯 FTP honeypot listening on :{self.port}")
        async with server:
            await server.serve_forever()


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP Honeypot
# ══════════════════════════════════════════════════════════════════════════════
class HTTPHoneypot:
    """Fake HTTP server — captures scanners, exploits, and credential stuffing."""

    FAKE_PAGES = {
        "/": b"<html><body><h1>Welcome</h1><form method='post' action='/login'><input name='username'><input name='password' type='password'><button>Login</button></form></body></html>",
        "/admin": b"<html><body><h1>Admin Panel</h1><form method='post'><input name='user'><input name='pass' type='password'><button>Login</button></form></body></html>",
        "/robots.txt": b"User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /.git\n",
        "/.env": b"DB_HOST=localhost\nDB_USER=root\nDB_PASS=password123\nAPP_KEY=base64:fakekey=\n",
        "/wp-login.php": b"<html><body>WordPress Login</body></html>",
    }

    def __init__(self, port: int, attacker_log: AttackerLog):
        self.port = port
        self.logger = attacker_log

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        src_ip, src_port = peer[0], peer[1]
        geo = GEOLOCATOR.lookup(src_ip)

        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            raw = data.decode(errors="replace")
            lines = raw.split("\r\n")
            if not lines:
                return

            # Parse request line
            request_line = lines[0]
            parts = request_line.split()
            method = parts[0] if len(parts) > 0 else "?"
            path = parts[1] if len(parts) > 1 else "/"

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.lower()] = v

            # Parse body for POST
            body = ""
            if "\r\n\r\n" in raw:
                body = raw.split("\r\n\r\n", 1)[1]

            self.logger.record("HTTP", src_ip, src_port, "REQUEST", {
                "method": method, "path": path,
                "user_agent": headers.get("user-agent", ""),
                "body": body[:500], "geo": geo,
            })

            # Detect attack patterns
            sqli_markers = ["'", "UNION", "SELECT", "1=1", "OR '1'='1"]
            lfi_markers = ["../", "etc/passwd", "win.ini"]
            for m in sqli_markers:
                if m in path or m in body:
                    self.logger.record("HTTP", src_ip, src_port, "ATTACK", {"type": "SQLi", "payload": (path + body)[:200]})
            for m in lfi_markers:
                if m in path:
                    self.logger.record("HTTP", src_ip, src_port, "ATTACK", {"type": "LFI", "payload": path[:200]})

            # Build response
            page = self.FAKE_PAGES.get(path, b"<html><body><h1>404 Not Found</h1></body></html>")
            status = "200 OK" if path in self.FAKE_PAGES else "404 Not Found"
            response = (
                f"HTTP/1.1 {status}\r\n"
                f"Server: Apache/2.4.41 (Ubuntu)\r\n"
                f"Content-Type: text/html\r\n"
                f"Content-Length: {len(page)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + page

            writer.write(response)
            await writer.drain()

        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def start(self):
        server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.port)
        log.info(f"🍯 HTTP honeypot listening on :{self.port}")
        async with server:
            await server.serve_forever()


# ══════════════════════════════════════════════════════════════════════════════
#  Telnet Honeypot
# ══════════════════════════════════════════════════════════════════════════════
class TelnetHoneypot:
    """Fake Telnet server — captures Mirai-style bot credential scans."""

    BANNER = b"\r\nUbuntu 20.04 LTS\r\n\r\nlogin: "

    def __init__(self, port: int, attacker_log: AttackerLog):
        self.port = port
        self.logger = attacker_log

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        src_ip, src_port = peer[0], peer[1]
        self.logger.record("TELNET", src_ip, src_port, "CONNECTION", {})

        try:
            writer.write(self.BANNER)
            await writer.drain()
            username = (await asyncio.wait_for(reader.readline(), timeout=30)).decode(errors="replace").strip()
            writer.write(b"Password: ")
            await writer.drain()
            password = (await asyncio.wait_for(reader.readline(), timeout=30)).decode(errors="replace").strip()

            self.logger.record("TELNET", src_ip, src_port, "AUTH_ATTEMPT", {
                "username": username, "password": password
            })

            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()

        except Exception:
            pass
        finally:
            self.logger.record("TELNET", src_ip, src_port, "DISCONNECT", {})
            try:
                writer.close()
            except Exception:
                pass

    async def start(self):
        server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.port)
        log.info(f"🍯 Telnet honeypot listening on :{self.port}")
        async with server:
            await server.serve_forever()


# ══════════════════════════════════════════════════════════════════════════════
class HoneypotOrchestrator:
    """Manages all honeypot services."""

    def __init__(self, log_dir: str = "honeypot_logs"):
        self.attacker_log = AttackerLog(log_dir)
        self.services = []

    def add_ssh(self, port: int):
        self.services.append(SSHHoneypot(port, self.attacker_log))

    def add_ftp(self, port: int):
        self.services.append(FTPHoneypot(port, self.attacker_log))

    def add_http(self, port: int):
        self.services.append(HTTPHoneypot(port, self.attacker_log))

    def add_telnet(self, port: int):
        self.services.append(TelnetHoneypot(port, self.attacker_log))

    async def run(self):
        print("""
 ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
 ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
 ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║   
 ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║   
 ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║   
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝  
        """)
        tasks = [asyncio.create_task(s.start()) for s in self.services]
        log.info(f"🍯 {len(self.services)} honeypot(s) active — waiting for attackers...")
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            self.attacker_log.close()


# ══════════════════════════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(description="🍯 Multi-protocol Honeypot Framework")
    p.add_argument("--ssh", type=int, metavar="PORT", help="SSH honeypot port (e.g. 2222)")
    p.add_argument("--ftp", type=int, metavar="PORT", help="FTP honeypot port (e.g. 2121)")
    p.add_argument("--http", type=int, metavar="PORT", help="HTTP honeypot port (e.g. 8080)")
    p.add_argument("--telnet", type=int, metavar="PORT", help="Telnet honeypot port (e.g. 2323)")
    p.add_argument("--all", action="store_true", help="Enable all services on default ports")
    p.add_argument("--log-dir", default="honeypot_logs", help="Directory to write event logs")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    orch = HoneypotOrchestrator(log_dir=args.log_dir)

    if args.all:
        orch.add_ssh(2222)
        orch.add_ftp(2121)
        orch.add_http(8080)
        orch.add_telnet(2323)
    else:
        if args.ssh:
            orch.add_ssh(args.ssh)
        if args.ftp:
            orch.add_ftp(args.ftp)
        if args.http:
            orch.add_http(args.http)
        if args.telnet:
            orch.add_telnet(args.telnet)

    if not orch.services:
        print("No services configured. Use --all or specify --ssh/--ftp/--http/--telnet")
        sys.exit(1)

    try:
        asyncio.run(orch.run())
    except KeyboardInterrupt:
        log.info("Honeypot shutdown.")
