"""Minimal firegex client, derived from Pwnzer0tt1/firegex @ 16d0bfd
(backend/routers/nfregex.py, backend/app.py). nfregex services + DROP regexes;
regexes are base64-encoded and created inactive by default."""

import base64
import json
import urllib.parse
import urllib.request
from urllib.error import HTTPError


class FiregexClient:
    def __init__(self, base_url, password):
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.token = None

    def login(self):
        # POST /api/login (form: username=login, password) -> {access_token, token_type}
        data = urllib.parse.urlencode({"username": "login", "password": self.password}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/login", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req) as r:
                self.token = json.loads(r.read()).get("access_token")
                return bool(self.token)
        except HTTPError:
            return False

    def _request(self, method, endpoint, json_data=None):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        data = None
        if json_data is not None:
            data = json.dumps(json_data).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base_url}{endpoint}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as r:
                return json.loads(r.read())
        except HTTPError as e:
            try:
                return json.loads(e.read())
            except Exception:
                return None

    def list_services(self):
        return self._request("GET", "/api/nfregex/services") or []

    def add_service(self, name, port, proto, ip_int, fail_open=True):
        r = self._request("POST", "/api/nfregex/services", {
            "name": name, "port": port, "proto": proto, "ip_int": ip_int, "fail_open": fail_open,
        })
        return r.get("service_id") if r and r.get("status") == "ok" else None

    def add_regex(self, service_id, regex, mode="B", active=False, is_case_sensitive=False):
        # regex is base64-encoded over the wire; created INACTIVE by default.
        if isinstance(regex, str):
            regex = regex.encode()
        b64 = base64.b64encode(regex).decode()
        r = self._request("POST", "/api/nfregex/regexes", {
            "service_id": service_id, "regex": b64, "mode": mode,
            "is_case_sensitive": is_case_sensitive, "active": active,
        })
        if not (r and r.get("status") == "ok"):
            return None
        for existing in self.get_service_regexes(service_id):
            if existing.get("regex") == b64:
                return existing.get("id")
        return None

    def set_regex_active(self, regex_id, active):
        endpoint = f"/api/nfregex/regexes/{regex_id}/{'enable' if active else 'disable'}"
        r = self._request("POST", endpoint)
        return bool(r and r.get("status") == "ok")

    def delete_regex(self, regex_id):
        r = self._request("DELETE", f"/api/nfregex/regexes/{regex_id}")
        return bool(r and r.get("status") == "ok")

    def get_service_regexes(self, service_id):
        return self._request("GET", f"/api/nfregex/services/{service_id}/regexes") or []

    def get_metrics(self):
        # GET /api/nfregex/metrics -> Prometheus PLAINTEXT (not JSON).
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        req = urllib.request.Request(f"{self.base_url}/api/nfregex/metrics", headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req) as r:
                return r.read().decode("utf-8", errors="ignore")
        except HTTPError:
            return ""
