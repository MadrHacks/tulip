import os
import tempfile
import unittest

from config import load_config


class TestLoadConfig(unittest.TestCase):
    def test_reads_unified_config(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "game.yml"), "w") as f:
                f.write(
                    "team_id: 36\n"
                    "ip_format: '10.60.{}.1'\n"
                    "flag_regex: '[A-Z0-9]{31}='\n"
                    "flag_ids_url: http://10.10.0.1:8081/flagIds\n"
                )
            with open(os.path.join(d, "farm.yml"), "w") as f:
                f.write("server_password: secret\napi_token: ''\n")
            cfg = load_config(d)
        self.assertEqual(cfg.team_id, 36)
        self.assertEqual(cfg.ip_format, "10.60.{}.1")
        self.assertEqual(cfg.flagids_url, "http://10.10.0.1:8081/flagIds")
        self.assertEqual(cfg.farm_token, "secret")  # falls back to server_password

    def test_defaults_when_missing(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(d)
        self.assertEqual(cfg.team_id, -1)
        self.assertEqual(cfg.ip_format, "10.60.{}.1")


if __name__ == "__main__":
    unittest.main()
