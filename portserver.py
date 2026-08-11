#!/usr/bin/env python3
"""
portserver.py -- a minimal, single-file HTTP server for serving MacPorts-style
distfiles and their on-the-fly RMD160 signatures, using a socket handed to it
by launchd (socket activation), so it can bind to a privileged port without
running as root.

Usage:
    portserver.py <private-key.pem> <directory>

It serves exactly three kinds of GET requests:

    GET /pubkey.pem
        Returns the RSA public key corresponding to <private-key.pem>.

    GET /<anything>.tbz2
        Serves that file from <directory> (arbitrary depth of subdirectories
        is allowed, e.g. /clang-22/clang-22-22.1.8_0+analyzer.darwin_25.x86_64.tbz2).
        Path traversal and symlink escapes out of <directory> are rejected.

    GET /<anything>.tbz2.rmd160
        Computes an RSA signature over the RIPEMD160 digest of the
        corresponding .tbz2 file (i.e. `openssl dgst -ripemd160 -sign
        <private-key.pem>`) and returns the raw signature bytes. Nothing is
        written to disk -- it's generated fresh for each request.

Everything else results in a 404.

launchd socket activation
--------------------------
This process does not bind or listen on a socket itself. It expects to be
started by launchd with a Sockets entry (see the SOCKET_NAME constant below)
in its plist, and retrieves the listening socket via the launch_activate_socket(3)
API using ctypes. Example plist Sockets stanza:

    <key>Sockets</key>
    <dict>
        <key>portserver-http</key>
        <dict>
            <key>SockServiceName</key>
            <string>http</string>
        </dict>
    </dict>

Run it under launchd, not directly from a shell (launch_activate_socket will
fail with a clear error if there's no launchd-provided socket).
"""

import argparse
import ctypes
import ctypes.util
import http.server
import os
import socket
import socketserver
import subprocess
import sys
import urllib.parse

# This must match the key used in the launchd plist's Sockets dict.
SOCKET_NAME = "portserver-http"

OPENSSL = "/usr/bin/openssl"


# --------------------------------------------------------------------------
# launchd socket activation
# --------------------------------------------------------------------------

def launch_activate_socket(name):
    """
    Ask launchd for the file descriptor(s) it created for the Sockets entry
    named `name` in this process's plist, via launch_activate_socket(3).

    Returns a list of file descriptors (usually exactly one).
    """
    libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)

    launch_activate_socket_fn = libsystem.launch_activate_socket
    launch_activate_socket_fn.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_int)),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    launch_activate_socket_fn.restype = ctypes.c_int

    fd_array = ctypes.POINTER(ctypes.c_int)()
    fd_count = ctypes.c_size_t()

    err = launch_activate_socket_fn(
        name.encode("utf-8"), ctypes.byref(fd_array), ctypes.byref(fd_count)
    )
    if err != 0:
        raise OSError(
            err,
            f"launch_activate_socket failed for socket name {name!r} "
            f"(errno {err}); is this process actually running under launchd "
            f"with a matching Sockets entry?",
        )

    try:
        fds = [fd_array[i] for i in range(fd_count.value)]
    finally:
        libsystem.free(fd_array)

    return fds


class LaunchdHTTPServer(http.server.HTTPServer):
    """
    An HTTPServer that uses a pre-existing, already-bound-and-listening
    socket (as provided by launchd) instead of creating and binding its own.
    """

    def __init__(self, sock, RequestHandlerClass):
        # Deliberately skip TCPServer.__init__ (it would create a fresh
        # socket and try to bind it); go straight to BaseServer and wire
        # up the launchd-provided socket ourselves.
        self.socket = sock
        self.server_address = sock.getsockname()
        socketserver.BaseServer.__init__(self, self.server_address, RequestHandlerClass)
        host = self.server_address[0]
        self.server_name = socket.getfqdn(host)
        self.server_port = self.server_address[1]

    def server_bind(self):
        pass  # socket is already bound by launchd

    def server_activate(self):
        pass  # socket is already listening


# --------------------------------------------------------------------------
# Safe path resolution
# --------------------------------------------------------------------------

def resolve_within(base_dir_real, url_path):
    """
    Resolve a URL path (e.g. "/xz/xz-5.8.3_0.darwin_25.x86_64.tbz2") to an
    absolute filesystem path inside base_dir_real, refusing to leave it via
    "..", absolute-path tricks, or symlinks.

    Returns the real path if it names an existing regular file inside
    base_dir_real, otherwise None.
    """
    relative = url_path.lstrip("/")
    if not relative:
        return None

    # Reject NUL bytes and other obviously bogus input up front.
    if "\x00" in relative:
        return None

    candidate = os.path.join(base_dir_real, relative)
    real_candidate = os.path.realpath(candidate)

    # realpath() resolves ".." components AND symlinks (including
    # symlinked intermediate directories), so checking containment against
    # the fully-resolved path catches both traversal and symlink escapes.
    if real_candidate != base_dir_real and not real_candidate.startswith(
        base_dir_real + os.sep
    ):
        return None

    if not os.path.isfile(real_candidate):
        return None

    return real_candidate


# --------------------------------------------------------------------------
# Request handler
# --------------------------------------------------------------------------

class DistfileRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "portserver/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(parsed.path)

        if path == "/pubkey.pem":
            self._serve_bytes(self.server.pubkey_pem, "application/x-pem-file")
            return

        if path.endswith(".tbz2.rmd160"):
            self._serve_signature(path)
            return

        if path.endswith(".tbz2"):
            self._serve_file(path)
            return

        self.send_error(404, "Not Found")

    # -- handlers ----------------------------------------------------------

    def _serve_file(self, url_path):
        real_path = resolve_within(self.server.base_dir, url_path)
        if real_path is None:
            self.send_error(404, "Not Found")
            return

        try:
            size = os.path.getsize(real_path)
            f = open(real_path, "rb")
        except OSError:
            self.send_error(404, "Not Found")
            return

        with f:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-bzip-compressed-tar")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            self._copy_stream(f)

    def _serve_signature(self, url_path):
        tbz2_url_path = url_path[: -len(".rmd160")]
        real_path = resolve_within(self.server.base_dir, tbz2_url_path)
        if real_path is None:
            self.send_error(404, "Not Found")
            return

        try:
            result = subprocess.run(
                [
                    OPENSSL,
                    "dgst",
                    "-ripemd160",
                    "-sign",
                    self.server.private_key_path,
                    real_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            self.log_error("failed to invoke openssl: %s", exc)
            self.send_error(500, "Internal Server Error")
            return

        if result.returncode != 0 or not result.stdout:
            self.log_error(
                "openssl signing failed for %s: %s",
                real_path,
                result.stderr.decode("utf-8", "replace").strip(),
            )
            self.send_error(500, "Internal Server Error")
            return

        self._serve_bytes(result.stdout, "text/binary")

    # -- helpers -------------------------------------------------------

    def _serve_bytes(self, data, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _copy_stream(self, f, chunk_size=64 * 1024):
        if self.command == "HEAD":
            return
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            self.wfile.write(chunk)

    def do_HEAD(self):
        # Reuse GET's logic; _serve_bytes/_copy_stream already skip the
        # body when self.command == "HEAD".
        self.do_GET()

    def log_message(self, fmt, *args):
        sys.stderr.write(
            "%s - - [%s] %s\n"
            % (self.address_string(), self.log_date_time_string(), fmt % args)
        )


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------

def load_public_key_pem(private_key_path):
    result = subprocess.run(
        [OPENSSL, "rsa", "-in", private_key_path, "-pubout"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        sys.exit(
            "error: could not derive public key from "
            f"{private_key_path}: {result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def main():
    parser = argparse.ArgumentParser(
        description="Serve MacPorts-style .tbz2 distfiles and on-the-fly "
        ".tbz2.rmd160 signatures over a launchd-activated socket."
    )
    parser.add_argument("private_key", help="path to an RSA private key (PEM)")
    parser.add_argument("directory", help="directory containing .tbz2 files to serve")
    args = parser.parse_args()

    private_key_path = os.path.abspath(args.private_key)
    if not os.path.isfile(private_key_path):
        sys.exit(f"error: {private_key_path} is not a file")

    base_dir = os.path.realpath(args.directory)
    if not os.path.isdir(base_dir):
        sys.exit(f"error: {base_dir} is not a directory")

    pubkey_pem = load_public_key_pem(private_key_path)

    fds = launch_activate_socket(SOCKET_NAME)
    if len(fds) != 1:
        sys.exit(
            f"error: expected exactly one socket for launchd Sockets key "
            f"{SOCKET_NAME!r}, got {len(fds)}"
        )

    sock = socket.socket(fileno=fds[0])

    httpd = LaunchdHTTPServer(sock, DistfileRequestHandler)
    httpd.base_dir = base_dir
    httpd.private_key_path = private_key_path
    httpd.pubkey_pem = pubkey_pem

    httpd.serve_forever()


if __name__ == "__main__":
    main()
