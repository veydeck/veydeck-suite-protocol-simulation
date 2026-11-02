#!/usr/bin/env python3
"""Run the engine's discovery acceptance matrix in an isolated network namespace.

Requires Python 3.11+, a built engine and (unless --skip-nmap) Nmap.
Binds standard service ports: run in a disposable container, not on a live host.
Artifacts contain synthetic test identities and credentials only.
"""

import argparse
import asyncio
import ftplib
import hashlib
import http.client
import imaplib
import json
import os
import poplib
import signal
import smtplib
import socket
import struct
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

PORTS = {
    "http": 80,
    "redis": 6379,
    "smtp": 25,
    "pop3": 110,
    "imap": 143,
    "ssh": 22,
    "ftp": 21,
    "rdp": 3389,
    "telnet": 23,
    "mysql": 3306,
    "postgresql": 5432,
    "smb": 445,
    "ldap": 389,
    "dns": 53,
    "mongodb": 27017,
    "memcached": 11211,
    "snmp": 161,
    "mqtt": 1883,
    "vnc": 5900,
}
CUSTOM = {
    "http": {
        "server_header": "nginx/1.24.0",
        "exploit_paths": [
            {
                "path": "/probe",
                "response_status": 403,
                "response_body": "probe",
                "response_headers": {"Server": "wrong"},
            }
        ],
    },
    "redis": {
        "server_version": "7.2.5",
        "require_auth": True,
        "password": "probe-secret",
    },
    "smtp": {
        "banner": "mail.test ESMTP Postfix",
        "hostname": "mail.test",
        "require_auth": True,
        "credentials": [{"username": "probe", "password": "probe-secret"}],
    },
    "pop3": {
        "banner": "Dovecot ready.",
        "require_auth": True,
        "credentials": [{"username": "probe", "password": "probe-secret"}],
    },
    "imap": {
        "banner": "Dovecot ready.",
        "require_auth": True,
        "credentials": [{"username": "probe", "password": "probe-secret"}],
    },
    "ssh": {"banner": "SSH-2.0-OpenSSH_9.6p1"},
    "ftp": {
        "banner": "ProFTPD 1.3.8 Server ready.",
        "credentials": [{"username": "probe", "password": "probe-secret"}],
    },
    "rdp": {},
    "telnet": {
        "banner": "Ubuntu 24.04 LTS",
        "credentials": [{"username": "probe", "password": "probe-secret"}],
    },
    "mysql": {
        "server_version": "8.0.36",
        "credentials": [{"username": "probe", "password": "probe-secret"}],
    },
    "postgresql": {
        "server_version": "16.2",
        "credentials": [{"username": "probe", "password": "probe-secret"}],
    },
    "smb": {"server_name": "PROBEHOST", "domain": "PROBEDOMAIN"},
    "ldap": {
        "base_dn": "dc=probe,dc=test",
        "vendor_name": "OpenLDAP",
        "vendor_version": "2.6.8",
    },
    "dns": {
        "records": {"probe.test": "192.0.2.53"},
        "server_version": "9.18.30",
        "server_name": "ns.probe.test",
    },
    "mongodb": {"server_version": "7.0.14", "hostname": "mongo.probe.test"},
    "memcached": {"server_version": "1.6.32"},
    "snmp": {
        "community": "public",
        "system_description": "Linux probe 6.8.0",
        "system_name": "probe.test",
    },
    "mqtt": {"allow_anonymous": True},
    "vnc": {"protocol_version": "3.8", "security_types": ["none", "vnc_auth"]},
}
DEFAULT = {name: {} for name in PORTS}
DEFAULT["dns"] = {"records": {"probe.test": "192.0.2.53"}}
DEFAULT["ldap"] = {"base_dn": "dc=lab,dc=example"}


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError(f"expected {size} bytes, received {len(data)}")
        data.extend(chunk)
    return bytes(data)


def until(sock, suffix):
    data = bytearray()
    while not data.endswith(suffix):
        chunk = sock.recv(512)
        if not chunk:
            raise EOFError(f"connection ended before {suffix!r}: {data!r}")
        data.extend(chunk)
        assert len(data) <= 8192
    return bytes(data)


def tlv(tag, value):
    length = len(value)
    size = bytes([length]) if length < 128 else b"\x82" + struct.pack(">H", length)
    return bytes([tag]) + size + value


def ber_value(data, offset=0):
    tag, length = data[offset : offset + 2]
    start = offset + 2
    if length & 128:
        count = length & 127
        length = int.from_bytes(data[start : start + count], "big")
        start += count
    return tag, data[start : start + length], start + length


def read_ber(sock):
    head = exact(sock, 2)
    length = head[1]
    if length & 128:
        encoded = exact(sock, length & 127)
        length = int.from_bytes(encoded, "big")
        head += encoded
    assert length <= 65536
    return head + exact(sock, length)


def mysql_packet(sock):
    header = exact(sock, 4)
    return exact(sock, int.from_bytes(header[:3], "little"))


def netbios(sock):
    length = int.from_bytes(exact(sock, 4), "big")
    assert length <= 65536
    return exact(sock, length)


def smb_header(command, message_id=1, session=0):
    out = bytearray(64)
    out[:4] = b"\xfeSMB"
    struct.pack_into("<H", out, 4, 64)
    struct.pack_into("<H", out, 12, command)
    struct.pack_into("<Q", out, 24, message_id)
    struct.pack_into("<Q", out, 40, session)
    return bytes(out)


def send_smb(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    return netbios(sock)


def probe(name, port, config, udp=False):
    """Independent wire assertions, plus Python's standard protocol clients."""
    host = "127.0.0.1"
    if name == "http":
        client = http.client.HTTPConnection(host, port, timeout=4)
        values = []
        for path in ["/", "/probe"]:
            client.request("GET", path)
            response = client.getresponse()
            values.append(response.getheader("Server"))
            response.read()
        client.close()
        assert values == [config.get("server_header", "nginx/1.24.0")] * 2, values
        return values
    if name == "smtp":
        client = smtplib.SMTP(timeout=4)
        code, greeting = client.connect(host, port)
        assert code == 220 and not greeting.startswith(b"220 "), greeting
        if "banner" in config:
            assert greeting.decode() == config["banner"]
        assert client.ehlo()[0] == 250
        if config.get("credentials"):
            assert client.login("probe", "probe-secret")[0] == 235
        client.quit()
        return greeting.decode()
    if name == "pop3":
        client = poplib.POP3(host, port, timeout=4)
        greeting = client.getwelcome()
        assert greeting.startswith(b"+OK ") and not greeting.startswith(b"+OK +OK")
        if "banner" in config:
            assert greeting == b"+OK " + config["banner"].encode()
        capabilities = client.capa()
        if config.get("credentials"):
            client.user("probe")
            client.pass_("probe-secret")
            client.stat()
        client.quit()
        return {"greeting": greeting.decode(), "capabilities": list(capabilities)}
    if name == "imap":
        client = imaplib.IMAP4(host, port, timeout=4)
        greeting = client.welcome
        assert greeting.startswith(b"* OK ") and not greeting.startswith(b"* OK * OK")
        if "banner" in config:
            assert greeting == b"* OK " + config["banner"].encode()
        if config.get("credentials"):
            assert client.login("probe", "probe-secret")[0] == "OK"
        client.logout()
        return greeting.decode()
    if name == "ftp":
        client = ftplib.FTP(timeout=4)
        greeting = client.connect(host, port)
        assert greeting.startswith("220 ") and not greeting.startswith("220 220")
        if "banner" in config:
            assert greeting == "220 " + config["banner"]
        client.sendcmd("FEAT")
        if config.get("credentials"):
            assert client.login("probe", "probe-secret").startswith("230")
        client.quit()
        return greeting
    if name == "dns":
        results = {}
        queries = [
            ("probe.test", 1, 1, "192.0.2.53"),
            ("version.bind", 16, 3, config.get("server_version", "9.18.30")),
            ("id.server", 16, 3, config.get("server_name", "dns.veydeck.local")),
        ]
        for name_, kind, cls, expected in queries:
            question = (
                b"".join(bytes([len(s)]) + s.encode() for s in name_.split("."))
                + b"\0"
                + struct.pack(">HH", kind, cls)
            )
            packet = struct.pack(">6H", 1234, 256, 1, 0, 0, 0) + question
            with socket.socket(
                type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
            ) as sock:
                sock.settimeout(4)
                sock.connect((host, port))
                if udp:
                    sock.send(packet)
                    response = sock.recv(4096)
                else:
                    # Deliberate fragmentation tests TCP framing.
                    framed = struct.pack(">H", len(packet)) + packet
                    sock.sendall(framed[:3])
                    sock.sendall(framed[3:])
                    response = exact(sock, int.from_bytes(exact(sock, 2), "big"))
            assert response[:2] == packet[:2] and response[6:8] == b"\0\1"
            assert response.endswith(
                socket.inet_aton(expected) if kind == 1 else expected.encode()
            )
            results[name_] = expected
        return results
    if name == "snmp":
        oid = bytes.fromhex("2b06010201010100")
        binding = tlv(0x30, tlv(6, oid) + tlv(5, b""))
        pdu = tlv(0xA0, tlv(2, b"\x01") + tlv(2, b"\0") * 2 + tlv(0x30, binding))
        packet = tlv(0x30, tlv(2, b"\x01") + tlv(4, b"public") + pdu)
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            sock.sendto(packet, (host, port))
            response = sock.recv(4096)
        expected = config.get("system_description", "Linux veydeck-snmp 6.8.0")
        assert expected.encode() in response, response.hex()
        return expected
    with socket.create_connection((host, port), timeout=4) as sock:
        sock.settimeout(4)
        if name == "ssh":
            line = sock.makefile("rb").readline()
            assert line.startswith(b"SSH-2.0-") and line.endswith(b"\r\n")
            if "banner" in config:
                assert line == config["banner"].encode() + b"\r\n"
            sock.sendall(b"SSH-2.0-ProtocolProbe\r\n")
            return line.decode().strip()
        if name == "telnet":
            data = until(sock, b"login: ")
            assert b"\xff\xfb" in data and b"\r\nlogin: " in data
            if "banner" in config:
                assert config["banner"].encode() in data
            if config.get("credentials"):
                sock.sendall(b"\xff\xfd\x01\xff\xfd\x03probe\r\n")
                until(sock, b"Password: ")
                sock.sendall(b"probe-secret\r\n")
                until(sock, b"$ ")
                sock.sendall(b"exit\r\n")
            return bytes(data).decode(errors="backslashreplace")
        if name == "redis":
            # Redis must remain silent until the first request.
            sock.settimeout(0.1)
            try:
                unsolicited = sock.recv(1)
                raise AssertionError(f"unsolicited Redis data: {unsolicited!r}")
            except TimeoutError:
                pass
            sock.settimeout(4)
            reader = sock.makefile("rb")
            if config.get("require_auth"):
                sock.sendall(b"INFO\r\n")
                assert reader.readline().startswith(b"-NOAUTH")
                sock.sendall(b"AUTH wrong\r\n")
                assert reader.readline().startswith(b"-ERR")
                sock.sendall(b"AUTH probe-secret\r\n")
                assert reader.readline() == b"+OK\r\n"
            sock.sendall(b"PI")
            sock.sendall(b"NG\r\nINFO\r\n")
            assert reader.readline() == b"+PONG\r\n"
            head = reader.readline()
            assert head.startswith(b"$"), head
            info = reader.read(int(head[1:]))
            assert reader.read(2) == b"\r\n"
            assert info.count(b"redis_version:") == 1
            assert (
                "redis_version:" + config.get("server_version", "6.2.14")
            ).encode() in info
            return info.decode()
        if name == "mysql":
            data = mysql_packet(sock)
            assert data[0] == 10
            version = data[1:].split(b"\0", 1)[0].decode()
            assert version == config.get("server_version", "8.0.36-veydeck")
            if config.get("credentials"):
                offset = 1 + len(version.encode()) + 1 + 4
                seed = data[offset : offset + 8] + data[offset + 27 : offset + 39]
                # Protocol 4.1: fixed fields after first seed are 1+2+1+2+2+1+10=19 bytes.
                assert len(seed) == 20
                first = hashlib.sha1(b"probe-secret").digest()
                token = bytes(
                    a ^ b
                    for a, b in zip(
                        first,
                        hashlib.sha1(seed + hashlib.sha1(first).digest()).digest(),
                    )
                )
                payload = (
                    struct.pack("<IIB23x", 0x00088200, 0, 33)
                    + b"probe\0"
                    + bytes([20])
                    + token
                    + b"mysql_native_password\0"
                )
                sock.sendall(len(payload).to_bytes(3, "little") + b"\x01" + payload)
                assert mysql_packet(sock).startswith(b"\0")
                query = b"\x03SELECT VERSION()"
                sock.sendall(len(query).to_bytes(3, "little") + b"\0" + query)
                replies = [mysql_packet(sock) for _ in range(5)]
                assert version.encode() in replies[3]
            return version
        if name == "postgresql":
            sock.sendall(struct.pack(">II", 8, 80877103))
            assert exact(sock, 1) == b"N"
            startup = struct.pack(">I", 196608) + b"user\0probe\0database\0probe\0\0"
            sock.sendall(struct.pack(">I", len(startup) + 4) + startup)

            def message():
                kind = exact(sock, 1)
                data = exact(sock, int.from_bytes(exact(sock, 4), "big") - 4)
                return kind, data

            assert message() == (b"R", struct.pack(">I", 3))
            password = b"probe-secret\0"
            sock.sendall(b"p" + struct.pack(">I", len(password) + 4) + password)
            if not config.get("credentials"):
                kind, data = message()
                assert kind == b"E"
                return (
                    "PostgreSQL authentication challenge; version requires credentials"
                )
            params = {}
            while True:
                kind, data = message()
                if kind == b"S":
                    key, value, _ = data.split(b"\0", 2)
                    params[key.decode()] = value.decode()
                assert kind != b"E", data
                if kind == b"Z":
                    break
            assert params["server_version"] == config["server_version"]
            query = b"SELECT version()\0"
            sock.sendall(b"Q" + struct.pack(">I", len(query) + 4) + query)
            replies = []
            while True:
                kind, data = message()
                replies.append(data)
                if kind == b"Z":
                    break
            assert any(config["server_version"].encode() in v for v in replies)
            return params
        if name == "ldap":
            attrs = tlv(0x30, tlv(4, b"+") + tlv(4, b"*"))
            search = (
                tlv(4, b"")
                + tlv(10, b"\0") * 2
                + tlv(2, b"\0") * 2
                + tlv(1, b"\0")
                + tlv(0x87, b"objectClass")
                + attrs
            )
            packet = tlv(0x30, tlv(2, b"\x01\0") + tlv(0x63, search))
            sock.sendall(packet[:3])
            sock.sendall(packet[3:])
            entry = read_ber(sock)
            done = read_ber(sock)
            assert config["base_dn"].encode() in entry
            assert config.get("vendor_name", "OpenLDAP").encode() in entry
            _, envelope, _ = ber_value(entry)
            tag, msgid, offset = ber_value(envelope)
            assert tag == 2 and msgid == b"\x01\0"
            assert ber_value(envelope, offset)[0] == 0x64
            assert b"\x65" in done
            return {
                "base_dn": config["base_dn"],
                "vendor": config.get("vendor_name", "OpenLDAP"),
            }
        if name == "smb":
            body = struct.pack(
                "<HHHHI16sIHH", 36, 2, 1, 0, 0, b"\0" * 16, 0, 0, 0
            ) + struct.pack("<HH", 0x0202, 0x0210)
            reply = send_smb(sock, smb_header(0) + body)
            assert reply[:4] == b"\xfeSMB" and reply[8:12] == b"\0" * 4
            assert struct.unpack_from("<H", reply, 68)[0] == 0x0210
            ntlm = b"NTLMSSP\0" + struct.pack("<II", 1, 0x00088205) + b"\0" * 16
            setup = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(ntlm), 0)
            reply = send_smb(sock, smb_header(1, 2) + setup + ntlm)
            assert reply[8:12] == struct.pack("<I", 0xC0000016)
            start, length = struct.unpack_from("<HH", reply, 68)
            token = reply[start : start + length]
            assert b"NTLMSSP\0\x02\0\0\0" in token
            for key, default in [("server_name", "Veydeck"), ("domain", "LAB")]:
                assert config.get(key, default).encode("utf-16-le") in token
            return {
                key: config.get(key, default)
                for key, default in [("server_name", "Veydeck"), ("domain", "LAB")]
            }
        if name == "rdp":
            request = bytes.fromhex("030000130ee000000000000100080000000000")
            sock.sendall(request[:2])
            sock.sendall(request[2:])
            head = exact(sock, 4)
            reply = head + exact(sock, int.from_bytes(head[2:4], "big") - 4)
            assert reply[5] == 0xD0 and reply[11:] == bytes.fromhex("0200080000000000")
            with socket.create_connection((host, port), timeout=4) as second:
                tls_request = bytearray(request)
                tls_request[-4:] = struct.pack("<I", 3)
                second.sendall(tls_request)
                rejected = exact(second, 19)
                assert rejected[11:] == bytes.fromhex("0300080002000000")
            return "X.224; Standard RDP Security; TLS/NLA request rejected"
        if name == "mongodb":
            doc = (
                struct.pack("<i", 20)
                + b"\x10buildInfo\0"
                + struct.pack("<i", 1)
                + b"\0"
            )
            assert len(doc) == 20
            payload = struct.pack("<I", 0) + b"\0" + doc
            packet = struct.pack("<iiii", len(payload) + 16, 42, 0, 2013) + payload
            sock.sendall(packet)
            head = exact(sock, 16)
            length, _, response_to, opcode = struct.unpack("<iiii", head)
            data = exact(sock, length - 16)
            assert response_to == 42 and opcode == 2013
            expected = config.get("server_version", "7.0.14-veydeck")
            assert expected.encode() in data
            return expected
        if name == "memcached":
            sock.sendall(b"ver")
            sock.sendall(b"sion\r\nstats\r\n")
            reader = sock.makefile("rb")
            version = config.get("server_version", "1.6.24")
            assert reader.readline() == f"VERSION {version}\r\n".encode()
            stats = []
            while (line := reader.readline()) != b"END\r\n":
                assert line
                stats.append(line)
            assert b"STAT version " + version.encode() + b"\r\n" in stats
            return version
        if name == "mqtt":
            connect = b"\x10\x11\x00\x04MQTT\x04\x02\x00\x3c\x00\x05probe"
            sock.sendall(connect[:4])
            sock.sendall(connect[4:])
            assert exact(sock, 4) == b"\x20\x02\x00\x00"
            sock.sendall(b"\xc0\0")
            assert exact(sock, 2) == b"\xd0\0"
            sock.sendall(b"\xe0\0")
            with socket.create_connection((host, port), timeout=4) as second:
                connect5 = b"\x10\x12\x00\x04MQTT\x05\x02\x00\x3c\x00\x00\x05probe"
                second.sendall(connect5)
                assert exact(second, 5) == b"\x20\x03\x00\x00\x00"
            return "MQTT 3.1.1/5 CONNACK; PINGRESP"
        if name == "vnc":
            banner = exact(sock, 12)
            assert banner == b"RFB 003.008\n"
            sock.sendall(banner)
            types = exact(sock, exact(sock, 1)[0])
            assert 1 in types
            sock.sendall(b"\x01")
            assert exact(sock, 4) == b"\0" * 4
            with socket.create_connection((host, port), timeout=4) as second:
                assert exact(second, 12) == banner
                second.sendall(b"RFB 003.003\n")
                assert exact(second, 4) == b"\0\0\0\x01"
            if "vnc_auth" in config.get("security_types", []):
                with socket.create_connection((host, port), timeout=4) as second:
                    assert exact(second, 12) == banner
                    second.sendall(banner)
                    assert 2 in exact(second, exact(second, 1)[0])
                    second.sendall(b"\x02")
                    assert len(exact(second, 16)) == 16
                    second.sendall(b"\0" * 16)
                    assert exact(second, 4) == b"\0\0\0\x01"
            return {"protocol": banner.decode().strip(), "security_types": list(types)}
    raise AssertionError(f"missing probe for {name}")


class UdpForward(asyncio.DatagramProtocol):
    def __init__(self, port):
        self.port = port
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        async def relay():
            sock = socket.socket(type=socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                loop = asyncio.get_running_loop()
                await loop.sock_sendto(sock, data, ("127.0.0.1", self.port))
                reply, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), 4)
                self.transport.sendto(reply, addr)
            except (TimeoutError, OSError):
                # Unrelated Nmap UDP probes are expected to receive no response.
                pass
            finally:
                sock.close()

        task = asyncio.create_task(relay())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)


async def forward_tcp(reader, writer, port):
    try:
        upstream, remote = await asyncio.open_connection("127.0.0.1", port)

        async def copy(source, target):
            try:
                while data := await source.read(65536):
                    target.write(data)
                    await target.drain()
            finally:
                target.close()

        await asyncio.gather(copy(reader, remote), copy(upstream, writer))
    except (OSError, ConnectionError):
        writer.close()


async def callback(reader, writer, output):
    try:
        header = await reader.readuntil(b"\r\n\r\n")
        length = next(
            (
                int(v.split(b":", 1)[1])
                for v in header.split(b"\r\n")
                if v.lower().startswith(b"content-length:")
            ),
            0,
        )
        payload = await reader.readexactly(length)
        with (output / "events.jsonl").open("ab") as events:
            events.write(payload + b"\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        )
        await writer.drain()
    finally:
        writer.close()


async def nmap_scan(args, output, mapped, configs):
    offset = 20000 if mapped else 0
    excluded = {"snmp", "smb", "ldap"}
    authenticated_redis = configs["redis"].get("require_auth", False)
    if authenticated_redis:
        excluded.add("redis")
    ports = sorted(
        {port + offset for name, port in PORTS.items() if name not in excluded}
    )
    udp = [53 + offset, 161 + offset]
    prefix = output / ("mapped" if mapped else "standard")
    command = [
        args.nmap,
        "-n",
        "-Pn",
        "-sT",
        "-sU",
        "-sV",
        "--version-light",
        "--max-retries",
        "1",
        "--host-timeout",
        "120s",
        "-p",
        "T:" + ",".join(map(str, ports)) + ",U:" + ",".join(map(str, udp)),
        "-oX",
        str(prefix) + ".xml",
        "127.0.0.1",
    ]
    if args.nmap_data:
        command[1:1] = ["--datadir", args.nmap_data]
    (prefix.with_suffix(".command.json")).write_text(
        json.dumps(command, indent=2) + "\n"
    )
    with prefix.with_suffix(".log").open("wb") as log:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=log, stderr=subprocess.STDOUT
        )
        await asyncio.wait_for(process.wait(), 140)
    if process.returncode:
        raise RuntimeError(f"Nmap exited {process.returncode}: {prefix}.log")
    root = ET.parse(str(prefix) + ".xml").getroot()
    results = []
    expected = {
        ("tcp", p + offset): name for name, p in PORTS.items() if name not in excluded
    }
    expected.update({("udp", 53 + offset): "dns", ("udp", 161 + offset): "snmp"})
    aliases = {
        "postgresql": {"postgresql"},
        "rdp": {"ms-wbt-server"},
        "smb": {"microsoft-ds"},
        "mongodb": {"mongodb"},
        "vnc": {"vnc"},
        "mqtt": {"mqtt"},
        "dns": {"domain"},
    }
    for port in root.findall(".//port"):
        key = (port.get("protocol"), int(port.get("portid")))
        name = expected[key]
        service = port.find("service")
        data = dict(service.attrib) if service is not None else {}
        success = (
            port.find("state").get("state") == "open"
            and data.get("method") == "probed"
            and data.get("name") in aliases.get(name, {name})
        )
        results.append(
            {
                "protocol": name,
                "transport": key[0],
                "port": key[1],
                "passed": success,
                "service": data,
            }
        )
    assert len(results) == len(expected), f"incomplete Nmap output: {prefix}"

    # A light pass is sufficient for already recognized services. Retry unknown
    # endpoints independently with all official probes (important on mapped ports).
    async def retry(row):
        retry_prefix = (
            output
            / f"{'mapped' if mapped else 'standard'}-{row['transport']}-{row['port']}-full"
        )
        scan_type = "-sU" if row["transport"] == "udp" else "-sT"
        retry_command = [
            args.nmap,
            "-n",
            "-Pn",
            scan_type,
            "-sV",
            "--version-all",
            "--max-retries",
            "1",
            "--host-timeout",
            "300s",
            "-oX",
            str(retry_prefix) + ".xml",
            "-p",
            str(row["port"]),
            "127.0.0.1",
        ]
        if args.nmap_data:
            retry_command[1:1] = ["--datadir", args.nmap_data]
        retry_prefix.with_suffix(".command.json").write_text(
            json.dumps(retry_command, indent=2) + "\n"
        )
        with retry_prefix.with_suffix(".log").open("wb") as log:
            process = await asyncio.create_subprocess_exec(
                *retry_command, stdout=log, stderr=subprocess.STDOUT
            )
            await asyncio.wait_for(process.wait(), 320)
        retry_root = ET.parse(str(retry_prefix) + ".xml").getroot()
        port = retry_root.find(".//port")
        service = None if port is None else port.find("service")
        details = {} if service is None else dict(service.attrib)
        row["initial_service"] = row["service"]
        row["service"] = details
        row["passed"] = (
            process.returncode == 0
            and port is not None
            and port.find("state").get("state") == "open"
            and details.get("method") == "probed"
            and details.get("name") in aliases.get(row["protocol"], {row["protocol"]})
        )

    await asyncio.gather(*(retry(row) for row in results if not row["passed"]))
    smb_port = PORTS["smb"] + offset
    script_prefix = output / ("mapped-smb" if mapped else "standard-smb")
    script_command = [
        args.nmap,
        "-n",
        "-Pn",
        "-sT",
        "-p",
        str(smb_port),
        "--script",
        "smb-protocols",
        "--script-args",
        f"smbport={smb_port}",
        "-oX",
        str(script_prefix) + ".xml",
        "127.0.0.1",
    ]
    if args.nmap_data:
        script_command[1:1] = ["--datadir", args.nmap_data]
    script_prefix.with_suffix(".command.json").write_text(
        json.dumps(script_command, indent=2) + "\n"
    )
    with script_prefix.with_suffix(".log").open("wb") as log:
        process = await asyncio.create_subprocess_exec(
            *script_command, stdout=log, stderr=subprocess.STDOUT
        )
        await asyncio.wait_for(process.wait(), 30)
    script_root = ET.parse(str(script_prefix) + ".xml").getroot()
    script = script_root.find(".//script[@id='smb-protocols']")
    dialects = (
        []
        if script is None
        else [element.text for element in script.findall(".//elem")]
    )
    results.append(
        {
            "protocol": "smb",
            "transport": "tcp",
            "port": smb_port,
            "passed": process.returncode == 0
            and "2:0:2" in dialects
            and "2:1:0" in dialects,
            "service": {"method": "NSE smb-protocols", "dialects": dialects},
        }
    )
    ldap_port = PORTS["ldap"] + offset
    ldap_prefix = output / ("mapped-ldap" if mapped else "standard-ldap")
    ldap_command = [
        args.nmap,
        "-n",
        "-Pn",
        "-sT",
        "-p",
        str(ldap_port),
        "--script",
        "+ldap-rootdse",
        "-oX",
        str(ldap_prefix) + ".xml",
        "127.0.0.1",
    ]
    if args.nmap_data:
        ldap_command[1:1] = ["--datadir", args.nmap_data]
    ldap_prefix.with_suffix(".command.json").write_text(
        json.dumps(ldap_command, indent=2) + "\n"
    )
    with ldap_prefix.with_suffix(".log").open("wb") as log:
        process = await asyncio.create_subprocess_exec(
            *ldap_command, stdout=log, stderr=subprocess.STDOUT
        )
        await asyncio.wait_for(process.wait(), 30)
    ldap_root = ET.parse(str(ldap_prefix) + ".xml").getroot()
    script = ldap_root.find(".//script[@id='ldap-rootdse']")
    details = "" if script is None else script.get("output", "")
    results.append(
        {
            "protocol": "ldap",
            "transport": "tcp",
            "port": ldap_port,
            "passed": process.returncode == 0
            and "namingContexts" in details
            and "vendorVersion" in details
            and "supportedLDAPVersion" in details,
            "service": {"method": "NSE ldap-rootdse", "rootdse": details},
        }
    )
    if authenticated_redis:
        redis_port = PORTS["redis"] + offset
        redis_prefix = output / (
            "mapped-redis-auth" if mapped else "standard-redis-auth"
        )
        redis_command = [
            args.nmap,
            "-n",
            "-Pn",
            "-sT",
            "-p",
            str(redis_port),
            "--script",
            "+redis-info",
            "--script-args",
            "creds.global=probe:" + configs["redis"]["password"],
            "-oX",
            str(redis_prefix) + ".xml",
            "127.0.0.1",
        ]
        if args.nmap_data:
            redis_command[1:1] = ["--datadir", args.nmap_data]
        redis_prefix.with_suffix(".command.json").write_text(
            json.dumps(redis_command, indent=2) + "\n"
        )
        with redis_prefix.with_suffix(".log").open("wb") as log:
            process = await asyncio.create_subprocess_exec(
                *redis_command, stdout=log, stderr=subprocess.STDOUT
            )
            await asyncio.wait_for(process.wait(), 30)
        redis_root = ET.parse(str(redis_prefix) + ".xml").getroot()
        script = redis_root.find(".//script[@id='redis-info']")
        version = None if script is None else script.find(".//elem[@key='Version']")
        version = None if version is None else version.text
        results.append(
            {
                "protocol": "redis",
                "transport": "tcp",
                "port": redis_port,
                "passed": process.returncode == 0
                and version == configs["redis"]["server_version"],
                "service": {"method": "NSE redis-info with AUTH", "version": version},
            }
        )
    return results


async def run_profile(args, name, configs):
    output = Path(args.output) / name
    output.mkdir(parents=True, exist_ok=True)
    processes, logs, servers, transports = [], [], [], []
    results = []
    try:
        for protocol, port in PORTS.items():
            transports_ = (
                ["tcp", "udp"]
                if protocol == "dns"
                else ["udp"]
                if protocol == "snmp"
                else ["tcp"]
            )
            endpoints = [
                {
                    "endpointId": "dns-" + t if protocol == "dns" else "main",
                    "transport": t,
                    "hostPort": port,
                    "containerPort": port,
                }
                for t in transports_
            ]
            config = {
                "schemaVersion": 1,
                "protocol": protocol,
                "ruleId": "probe-" + protocol,
                "ruleName": "Discovery acceptance",
                "instanceId": "probe-" + protocol,
                "callbackUrl": "http://127.0.0.1:18080/events",
                "callbackToken": "synthetic-test-token",
                "endpoints": endpoints,
                "behavior": configs[protocol],
            }
            (output / f"{protocol}.config.json").write_text(
                json.dumps(config, indent=2) + "\n"
            )
            env = dict(
                os.environ,
                VEYDECK_WORKLOAD_CONFIG_JSON=json.dumps(config),
                TOKIO_WORKER_THREADS="2",
                RUST_LOG="protocol_simulation_engine=debug",
            )
            log = (output / f"{protocol}.engine.log").open("wb")
            logs.append(log)
            processes.append(
                subprocess.Popen(
                    [args.engine], env=env, stdout=log, stderr=subprocess.STDOUT
                )
            )
            for transport in transports_:
                if transport == "tcp":

                    async def handler(reader, writer, port=port):
                        await forward_tcp(reader, writer, port)

                    servers.append(
                        await asyncio.start_server(handler, "127.0.0.1", port + 20000)
                    )
                else:
                    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                        lambda port=port: UdpForward(port),
                        local_addr=("127.0.0.1", port + 20000),
                    )
                    transports.append(udp)
        # Startup readiness, including explicit process failure detection.
        for _ in range(100):
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("engine exited during startup; see engine logs")
            try:
                for protocol, port in PORTS.items():
                    if protocol == "snmp":
                        continue
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.close()
                    await writer.wait_closed()
                break
            except OSError:
                await asyncio.sleep(0.05)
        else:
            raise TimeoutError("engines did not become ready")
        for mapped in [False, True]:
            for protocol, port in PORTS.items():
                for udp in [False, True] if protocol == "dns" else [protocol == "snmp"]:
                    row = {
                        "protocol": protocol,
                        "mapped": mapped,
                        "transport": "udp" if udp else "tcp",
                    }
                    try:
                        row["result"] = await asyncio.to_thread(
                            probe,
                            protocol,
                            port + (20000 if mapped else 0),
                            configs[protocol],
                            udp,
                        )
                        row["passed"] = True
                    except Exception as exc:
                        row.update(passed=False, error=f"{type(exc).__name__}: {exc}")
                    results.append(row)
                    print(
                        f"{name} {'mapped' if mapped else 'standard'} {protocol}/{row['transport']}: {'PASS' if row['passed'] else row['error']}",
                        flush=True,
                    )
        (output / "clients.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n"
        )
        nmap_results = []
        if not args.skip_nmap:
            scanned_layouts = await asyncio.gather(
                nmap_scan(args, output, False, configs),
                nmap_scan(args, output, True, configs),
            )
            for mapped, scanned in zip([False, True], scanned_layouts):
                for row in scanned:
                    row["mapped"] = mapped
                    print(
                        f"{name} Nmap {'mapped' if mapped else 'standard'} {row['protocol']}/{row['transport']}: {'PASS' if row['passed'] else 'FAIL'} {row['service']}",
                        flush=True,
                    )
                nmap_results.extend(scanned)
        report = {"profile": name, "clients": results, "nmap": nmap_results}
        (output / "results.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        )
        return all(r["passed"] for r in results + nmap_results)
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        for transport in transports:
            transport.close()
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
        for process in processes:
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()


async def main(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    metadata = {
        "engine_sha256": hashlib.sha256(Path(args.engine).read_bytes()).hexdigest(),
        "profiles": args.profile,
    }
    if not args.skip_nmap:
        metadata["nmap_version"] = subprocess.check_output(
            [args.nmap, "--version"], text=True
        )
        if args.nmap_data:
            metadata["nmap_service_probes_sha256"] = hashlib.sha256(
                (Path(args.nmap_data) / "nmap-service-probes").read_bytes()
            ).hexdigest()
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")

    async def receive_callback(reader, writer):
        await callback(reader, writer, output)

    callback_server = await asyncio.start_server(receive_callback, "127.0.0.1", 18080)
    async with callback_server:
        passed = True
        for profile in args.profile:
            passed = (
                await run_profile(
                    args, profile, DEFAULT if profile == "default" else CUSTOM
                )
                and passed
            )
        return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", default="target/debug/protocol-simulation-engine")
    parser.add_argument("--nmap", default="nmap")
    parser.add_argument("--nmap-data")
    parser.add_argument("--output", default="target/discovery-acceptance")
    parser.add_argument(
        "--profile",
        choices=["default", "custom"],
        nargs="+",
        default=["default", "custom"],
    )
    parser.add_argument("--skip-nmap", action="store_true")
    raise SystemExit(asyncio.run(main(parser.parse_args())))
