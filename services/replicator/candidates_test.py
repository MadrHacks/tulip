import unittest

from candidates import _ensure_plan_endpoint, _shape_candidates


class TestShapeCandidates(unittest.TestCase):
    def test_single_flow_tagged_template(self):
        single = [("svc", 7, 1234, {"segments": [], "slots": []})]
        out = _shape_candidates(single, [])
        self.assertEqual(len(out), 1)
        c = out[0]
        self.assertEqual(c["kind"], "template")
        self.assertEqual(c["sploit"], "cluster:svc:7")
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
        self.assertEqual(c["sploit"], "cluster:svc:7")
        self.assertEqual(c["plan"], plan)
        self.assertEqual(c["service"], "svc")
        self.assertEqual(c["port"], 1234)
        self.assertNotIn("template", c)

    def test_interactive_preferred_over_template_for_same_cluster(self):
        single = [("svc", 7, 1234, {"segments": [], "slots": []})]
        plan = {"service": "svc", "port": 1234, "steps": [], "links": []}
        interactive = [("svc", 7, 1234, plan)]
        out = _shape_candidates(single, interactive)
        # Only one candidate for the cluster, and it's the interactive one.
        sploits = [c["sploit"] for c in out]
        self.assertEqual(sploits, ["cluster:svc:7"])
        self.assertEqual(out[0]["kind"], "interactive")

    def test_distinct_clusters_both_kept(self):
        single = [("svc", 1, 10, {"segments": [], "slots": []})]
        interactive = [("svc", 2, 20, {"service": "svc", "port": 20, "steps": [], "links": []})]
        out = _shape_candidates(single, interactive)
        kinds = {c["sploit"]: c["kind"] for c in out}
        self.assertEqual(kinds, {"cluster:svc:1": "template", "cluster:svc:2": "interactive"})

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
