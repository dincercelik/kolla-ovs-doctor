"""A small SSH server for the tests, built on Paramiko. It runs commands with local bash."""
import socket
import subprocess
import threading
import time

import paramiko

SUDO = "sudo -n "


class Handler(paramiko.ServerInterface):
    """Accept one client key, and run each exec request in a thread."""

    def __init__(self, server):
        self.server = server

    def check_auth_publickey(self, username, key):
        if key.get_base64() != self.server.client_key.get_base64():
            return paramiko.AUTH_FAILED
        self.server.users.append(username)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_exec_request(self, channel, command):
        time.sleep(self.server.exec_delay)
        self.server.commands.append(command.decode())
        threading.Thread(target=run_command, args=(channel, command.decode()),
                         daemon=True).start()
        return True

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "publickey"


def run_command(channel, command):
    """Run command with bash, without its sudo prefix, and pipe it through the channel."""
    if command.startswith(SUDO):
        command = command[len(SUDO):]
    process = subprocess.Popen(["bash", "-c", command], stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def send(stream, write):
        for chunk in iter(lambda: stream.read1(65536), b""):
            write(chunk)

    pumps = [threading.Thread(target=send, args=(process.stdout, channel.sendall)),
             threading.Thread(target=send, args=(process.stderr, channel.sendall_stderr))]
    for pump in pumps:
        pump.start()
    for chunk in iter(lambda: channel.recv(65536), b""):
        process.stdin.write(chunk)
    process.stdin.close()
    for pump in pumps:
        pump.join()
    channel.send_exit_status(process.wait())
    channel.shutdown_write()
    channel.close()


class SSHServer:
    """An SSH server on 127.0.0.1 with a random port. It counts accepted connections."""

    def __init__(self):
        self.client_key = paramiko.RSAKey.generate(2048)
        self.commands, self.transports, self.users = [], [], []
        self.exec_delay = 0  # Seconds to wait before answering an exec request.
        self.host_key = paramiko.RSAKey.generate(2048)
        self.socket = socket.create_server(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    @property
    def accepted(self):
        return len(self.transports)

    def serve(self):
        while True:
            try:
                connection, _ = self.socket.accept()
            except OSError:
                return
            transport = paramiko.Transport(connection)
            transport.add_server_key(self.host_key)
            transport.start_server(server=Handler(self))
            self.transports.append(transport)

    def drop_connections(self):
        """Close every connection, as if the network dropped them."""
        for transport in self.transports:
            transport.close()

    def close(self):
        self.drop_connections()
        self.socket.close()
