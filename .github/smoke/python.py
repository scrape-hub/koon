"""Install test: koon as pip installed it sends a request to a local server."""
import http.server
import sys
import threading

import koon


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok" if "Chrome/" in self.headers["user-agent"] else b"no chrome user-agent"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
response = koon.KoonSync("chrome").get(f"http://127.0.0.1:{server.server_port}/")
if response.status_code != 200 or response.text != "ok":
    sys.exit(f"unexpected response: {response.status_code} {response.text}")
print(f"koon {koon.__version__} on Python {sys.version.split()[0]}: ok")
