import unittest

from candidates import _ensure_plan_endpoint, _shape_candidates


class TestShapeCandidates(unittest.TestCase):
    def test_single_flow_tagged_template(self):
        single = [("svc", 7, 1234, {"segments": [], "slots": []})]
        out = _shape_candidates(single, [])
        self.assertEqual(len(out), 1)
        c = out[0]
        self.assertEqual(c["kind"], "template")
        self.assertEqual(c["sploit"], "shape:svc:7")
        self.assertEqual(c["template"], {"segments": [], "slots": []})
        self.assertEqual(c["service"], "svc")
        self.assertEqual(c["port"], 1234)
        self.assertNotIn("plan", c)

    def test_interactive_shape(self):
        plan = {"service": "svc", "port": 1234, "steps": [], "links": []}
        out = _shape_candidates([], [("svc", 7, 1234, plan)])
        self.assertEqual(len(out), 1)
        c = out[0]
        self.assertEqual(c["kind"], "interactive")
        self.assertEqual(c["sploit"], "shape:svc:7")
        self.assertEqual(c["plan"], plan)
        self.assertEqual(c["service"], "svc")
        self.assertEqual(c["port"], 1234)
        self.assertNotIn("template", c)

    def test_interactive_preferred_over_template_for_same_shape(self):
        single = [("svc", 7, 1234, {"segments": [], "slots": []})]
        plan = {"service": "svc", "port": 1234, "steps": [], "links": []}
        interactive = [("svc", 7, 1234, plan)]
        out = _shape_candidates(single, interactive)
        # Only one candidate for the shape, and it's the interactive one.
        sploits = [c["sploit"] for c in out]
        self.assertEqual(sploits, ["shape:svc:7"])
        self.assertEqual(out[0]["kind"], "interactive")

    def test_distinct_shapes_both_kept(self):
        single = [("svc", 1, 10, {"segments": [], "slots": []})]
        interactive = [("svc", 2, 20, {"service": "svc", "port": 20, "steps": [], "links": []})]
        out = _shape_candidates(single, interactive)
        kinds = {c["sploit"]: c["kind"] for c in out}
        self.assertEqual(kinds, {"shape:svc:1": "template", "shape:svc:2": "interactive"})

    def test_shape_candidates_carry_sploit_port_and_payload(self):
        # A shape candidate must carry a "shape:" sploit, a non-null port, and the
        # right payload for its kind (template body vs interactive plan).
        single = [("boomthrow", 3, 8080, {"segments": [{"const": "x"}], "slots": []})]
        plan = {"service": "skypedia", "port": 1337, "steps": [{}], "links": []}
        interactive = [("skypedia", 9, 1337, plan)]
        out = _shape_candidates(single, interactive)
        by_sploit = {c["sploit"]: c for c in out}

        self.assertIn("shape:boomthrow:3", by_sploit)
        self.assertIn("shape:skypedia:9", by_sploit)

        tmpl = by_sploit["shape:boomthrow:3"]
        self.assertEqual(tmpl["kind"], "template")
        self.assertIsNotNone(tmpl["port"])
        self.assertEqual(tmpl["port"], 8080)
        self.assertEqual(tmpl["template"], {"segments": [{"const": "x"}], "slots": []})

        inter = by_sploit["shape:skypedia:9"]
        self.assertEqual(inter["kind"], "interactive")
        self.assertIsNotNone(inter["port"])
        self.assertEqual(inter["port"], 1337)
        self.assertEqual(inter["plan"], plan)

    def test_ensure_plan_endpoint_fills_missing(self):
        plan = {"steps": [], "links": []}
        _ensure_plan_endpoint(plan, "svc", 9999)
        self.assertEqual(plan["service"], "svc")
        self.assertEqual(plan["port"], 9999)

    def test_ensure_plan_endpoint_keeps_existing(self):
        plan = {"service": "orig", "port": 1, "steps": [], "links": []}
        _ensure_plan_endpoint(plan, "svc", 9999)
        self.assertEqual(plan["service"], "orig")
        self.assertEqual(plan["port"], 1)


if __name__ == "__main__":
    unittest.main()
