#!/usr/bin/env python3
"""
pythonrequests_tls — like pythonrequests, but emits HTTPS calls with
verify=False, suitable for flows that arrived already decrypted from
ad-capture (tagged "tls-decrypted" by the assembler).

Use this converter on services whose traffic is TLS-decrypted plaintext
(i.e. they came in via the ad-capture broker's Custom Block path). The
generated snippet:

  * uses requests with a Session
  * builds https://IP:PORT URLs
  * sets verify=False (CTF servers usually use self-signed certs)
  * forwards the original Host header verbatim — important when the
    original request had SNI / Host different from the dest IP (common
    behind reverse proxies)

Differences from pythonrequests.py: scheme=https, verify=False, no port
elision on 80 (because we'd elide 443 instead — and there's no harm in
always emitting :PORT for clarity).
"""
from typing import List

from helpers import Direction, Result, Stream, StreamChunk
from http_gzip import HTTPConverter, HTTPRequest, HTTPResponse


class PythonRequestsTLSConverter(HTTPConverter):

    requests_output: str
    target_host: str

    SHORTCUT_METHODS = ["get", "post", "put", "delete", "head", "patch"]

    def handle_http1_request(self, chunk: StreamChunk,
                             request: HTTPRequest) -> List[StreamChunk]:
        data = request.rfile.read()
        headers = {}
        for k, v in request.headers.items():
            headers[k] = v
        if request.command.lower() in self.SHORTCUT_METHODS:
            self.requests_output += f'r = s.{request.command.lower()}('
        else:
            self.requests_output += f'r = s.request({request.command!r}, '
        # Always emit the explicit https URL.
        self.requests_output += f'f"https://{self.target_host}{request.path}"'
        if len(headers) > 0:
            self.requests_output += f', headers={headers}'
        if len(data) > 0:
            self.requests_output += f', data={data}'
        # verify=False is on the Session, not per-call.
        self.requests_output += ')\n'
        return []

    def handle_http1_response(self, header: bytes, body: bytes,
                              chunk: StreamChunk,
                              response: HTTPResponse) -> List[StreamChunk]:
        return []

    def handle_stream(self, stream: Stream) -> Result:
        # Suppress urllib3's InsecureRequestWarning that fires once per
        # process when verify=False — keeps the generated script's output
        # readable during exploit dev.
        self.requests_output = f'''#!/usr/bin/env python3
import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IP = '{stream.Metadata.ServerHost}'
# IP = sys.argv[1]

# Generated from stream {stream.Metadata.StreamID} (tls-decrypted)
s = requests.Session()
s.verify = False

'''
        # Always include the port — for TLS-decrypted flows the original
        # server might have been on a non-standard port, and 443-vs-other
        # matters for SNI/connection setup.
        self.target_host = f'{{IP}}:{stream.Metadata.ServerPort}'
        result = super().handle_stream(stream)

        return Result(result.Chunks + [
            StreamChunk(Direction.CLIENTTOSERVER,
                        self.requests_output.encode())
        ])


if __name__ == "__main__":
    PythonRequestsTLSConverter().run()
