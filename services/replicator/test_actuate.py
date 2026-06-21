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

    def test_fanout_refuses_unproven_sploit(self):
        r = Replicator(_cfg(), armed=False)
        with self.assertRaises(ValueError):
            r.fanout(self._template(), "svc:1", "svc", 9999, [(1, "10.60.1.1")])

    def test_nop_proof_disarmed_does_not_prove(self):
        # disarmed nop_proof captures nothing, so the sploit stays unproven and
        # fan-out is still refused.
        r = Replicator(_cfg(), armed=False)
        self.assertEqual(r.nop_proof(self._template(), "svc:1", "svc", 9999, nop_team=0), [])
        self.assertNotIn("svc:1", r.proven)


class TestChainGates(unittest.TestCase):
    def _plan(self):
        return {
            "steps": [
                {"template": {"segments": [{"const": base64.b64encode(b"PING").decode()}],
                              "slots": []}, "service": "svc", "port": 9999},
            ],
            "links": [],
        }

    def test_disarmed_does_not_replay(self):
        # armed=False: returns without touching the network (a bad ip/port would
        # raise if it tried to connect).
        r = Replicator(_cfg(), armed=False)
        result = r.replay(self._plan(), "svc:1>svc:2", team=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["flags"], [])

    def test_refuses_own_team_even_when_armed(self):
        r = Replicator(_cfg(team_id=36), armed=True)
        with self.assertRaises(ValueError):
            r.replay(self._plan(), "svc:1>svc:2", team=36)

    def test_fanout_chain_refuses_unproven(self):
        r = Replicator(_cfg(), armed=False)
        with self.assertRaises(ValueError):
            r.fanout_chain(self._plan(), "svc:1>svc:2", [(1, "10.60.1.1")])

    def test_nop_proof_chain_disarmed_does_not_prove(self):
        r = Replicator(_cfg(), armed=False)
        result = r.nop_proof_chain(self._plan(), "svc:1>svc:2", nop_team=0)
        self.assertEqual(result["flags"], [])
        self.assertNotIn("svc:1>svc:2", r.proven)


if __name__ == "__main__":
    unittest.main()
