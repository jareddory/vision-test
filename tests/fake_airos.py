#!/usr/bin/env python3
"""
fake_airos.py - tiny stand-in for an airOS 8 radio, for local testing only.
Implements POST /api/auth (sets cookie + X-Csrf-Id), POST /stakick.cgi, POST /logout.cgi.
Records every request in FakeAirOS.calls. Never talk to a real radio in tests.

FakeAirOSSSH is a password-only SSH server (paramiko) for /rename-cpe tests. Each exec command
runs through /bin/sh with /tmp/system.cfg, cfgmtd and /usr/etc/rc.d/rc.softrestart redirected
to a temp folder, so the service's real shell commands (the s() function, sed, cfgmtd,
softrestart) are exercised end to end. Records commands in FakeAirOSSSH.commands.
"""
import http.server, json, os, socket, ssl, subprocess, tempfile, threading, time, urllib.parse


class FakeAirOS:
    def __init__(self, username="testuser", password="testpass", host="127.0.0.1", port=0,
                 kick_status=200, tls=True):
        self.username, self.password = username, password
        self.kick_status = kick_status
        self.calls = []
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _form(self):
                n = int(self.headers.get("Content-Length") or 0)
                return dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))

            def _send(self, code, body, headers=None):
                b = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                form = self._form()
                fake.calls.append({"path": self.path, "form": form, "headers": dict(self.headers)})
                if self.path == "/api/auth":
                    if form.get("username") == fake.username and form.get("password") == fake.password:
                        return self._send(200, {"auth": True}, {"X-Csrf-Id": "csrf123",
                                                                "Set-Cookie": "AIROS_SESSIONID=sess1; Path=/"})
                    return self._send(403, {"error": "bad login"})
                if self.path == "/stakick.cgi":
                    if self.headers.get("X-Csrf-Id") != "csrf123" or "sess1" not in (self.headers.get("Cookie") or ""):
                        return self._send(403, {"error": "no session"})
                    return self._send(fake.kick_status, {"ok": fake.kick_status == 200})
                if self.path == "/logout.cgi":
                    return self._send(200, {})
                return self._send(404, {"error": "not found"})

        self.httpd = http.server.ThreadingHTTPServer((host, port), H)
        if tls:
            d = tempfile.mkdtemp()
            cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=fake-airos", "-keyout", key, "-out", cert],
                           check=True, capture_output=True)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


# airOS 8.7.25 style config, trimmed to the keys /rename-cpe touches plus a few neighbours
SAMPLE_CFG = """aaa.status=disabled
resolv.host.1.name=Mike Roberts
resolv.host.1.status=enabled
snmp.community=BTWI
snmp.contact=BTWI
snmp.location=HUT
snmp.status=enabled
syslog.remote.ip=10.55.12.244
syslog.remote.port=514
syslog.remote.status=enabled
syslog.status=enabled
users.1.name=BTTW
"""

_HOST_KEY = None


class FakeAirOSSSH:
    def __init__(self, cfg=SAMPLE_CFG, username="BTTW", password="sshpass", host="127.0.0.1", port=0,
                 sabotage_key=None, drop_on_restart=False, save_exit=0, restart_exit=0,
                 command_delay=0, drop_backup=False, host_key=None):
        import paramiko
        global _HOST_KEY
        if host_key is not None:
            self.host_key = host_key
        else:
            if _HOST_KEY is None:
                _HOST_KEY = paramiko.RSAKey.generate(2048)
            self.host_key = _HOST_KEY
        self.username, self.password = username, password
        self.sabotage_key, self.drop_on_restart = sabotage_key, drop_on_restart
        self.command_delay, self.drop_backup = command_delay, drop_backup
        self.save_exit, self.restart_exit = save_exit, restart_exit
        self.commands, self.logins = [], 0
        self.dir = tempfile.mkdtemp(prefix="fake-airos-ssh-")
        self.cfg_path = os.path.join(self.dir, "system.cfg")
        self.saved_path = os.path.join(self.dir, "saved.cfg")
        self.restarts = 0
        with open(self.cfg_path, "w") as f:
            f.write(cfg)
        bindir = os.path.join(self.dir, "bin")
        os.mkdir(bindir)
        self._write_stub(os.path.join(bindir, "cfgmtd"),
                         f'cp "{self.cfg_path}" "{self.saved_path}"\n'
                         'echo "Found  Active on[1] ..."; echo "Found Backup1 on[2] ..."\n'
                         'echo "Storing Active[2] ... [%100]"; echo "Active->Backup[1] ... [%100]"\n'
                         f"exit {save_exit}\n")
        self._write_stub(os.path.join(bindir, "rc.softrestart"),
                         'echo "Fixup Startup_list ...Done."\n'
                         'echo "RTNETLINK answers: Cannot assign requested address" >&2\n'
                         'echo "RTNETLINK answers: File exists" >&2\n'
                         f"exit {restart_exit}\n")
        self.bindir = bindir
        fake = self

        class Server(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return "password"

            def check_auth_password(self, username, password):
                if username == fake.username and password == fake.password:
                    fake.logins += 1
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                threading.Thread(target=fake._exec, args=(channel, command.decode()), daemon=True).start()
                return True

        self._server_cls = Server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.transports = []
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    @staticmethod
    def _write_stub(path, body):
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)

    def _accept(self):
        import paramiko
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(self.host_key)
            self.transports.append(t)
            try:
                t.start_server(server=self._server_cls())
            except Exception:
                continue

    def rotate_host_key(self):
        import paramiko
        self.host_key = paramiko.RSAKey.generate(2048)

    def _exec(self, channel, command):
        self.commands.append(command)
        if self.command_delay:
            time.sleep(self.command_delay)
        is_restart = "rc.softrestart" in command
        if is_restart:
            self.restarts += 1
        local = (command.replace("/usr/etc/rc.d/rc.softrestart", os.path.join(self.bindir, "rc.softrestart"))
                 .replace("cfgmtd ", os.path.join(self.bindir, "cfgmtd") + " ")
                 .replace("/tmp/system.cfg", self.cfg_path))
        p = subprocess.run(["sh", "-c", local], capture_output=True, text=True, timeout=20)
        if self.sabotage_key and "btwi-cfg-edit" in command:
            self.set_key(self.sabotage_key, "sabotaged")
        if self.drop_backup and "btwi-cfg-edit" in command:
            bak = self.cfg_path + ".rename-bak"
            if os.path.exists(bak):
                os.remove(bak)
        if is_restart and self.drop_on_restart:
            channel.get_transport().close()  # session dies mid soft restart, no exit status
            return
        try:
            channel.sendall((p.stdout + p.stderr).encode())
            channel.send_exit_status(p.returncode)
            channel.shutdown_write()
            channel.close()
        except OSError:
            # The client already gave up (time budget or a closed session).
            pass

    # helpers for tests
    def cfg(self):
        return open(self.cfg_path).read()

    def saved(self):
        return open(self.saved_path).read() if os.path.exists(self.saved_path) else None

    def set_key(self, key, value):
        lines = [l for l in self.cfg().splitlines() if not l.startswith(key + "=")]
        with open(self.cfg_path, "w") as f:
            f.write("\n".join(lines + [f"{key}={value}"]) + "\n")

    def close(self):
        self._stop = True
        for t in self.transports:
            try:
                t.close()
            except Exception:
                pass
        self.sock.close()


if __name__ == "__main__":
    f = FakeAirOS(port=11443)
    print("fake airOS on https://127.0.0.1:11443 (user testuser / pass testpass); Ctrl+C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        f.close()
