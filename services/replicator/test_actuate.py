import base64
import unittest

from actuate import Config, Replicator, extract_flags


def _cfg(team_id=36):
    return Config(
        team_id=team_id,
        ip_format="10.60.{}.1",
        flag_regex=r"[A-Z0-9]{31}=",
        flagids_url="http://10.10.0.1:8081/flagIds",
        farm_url="http://farm",
        farm_token="tok",
    )


class TestExtractFlags(unittest.TestCase):
    def test_finds_flags(self):
        flag = "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234="  # 31 chars + '='
        data = b"HTTP/1.1 200 OK\r\n\r\nflag: " + flag.encode() + b" done"
        self.assertEqual(extract_flags(data, r"[A-Z0-9]{31}="), [flag])

    def test_none(self):
        self.assertEqual(extract_flags(b"nothing here", r"[A-Z0-9]{31}="), [])


class TestGates(unittest.TestCase):
    def _template(self):
        return {
            "segments": [{"const": base64.b64encode(b"PING").decode()}],
            "slots": [],
        }

    def test_disarmed_does_not_fire(self):
        # armed=False: returns [] without touching the network (a bad ip/port
        # would raise if it tried to connect).
        r = Replicator(_cfg(), armed=False)
        self.assertEqual(r.replicate(self._template(), "svc:1", "svc", 9999, team=1), [])

    def test_refuses_own_team_even_when_armed(self):
        r = Replicator(_cfg(team_id=36), armed=True)
        with self.assertRaises(ValueError):
            r.replicate(self._template(), "svc:1", "svc", 9999, team=36)


if __name__ == "__main__":
    unittest.main()
