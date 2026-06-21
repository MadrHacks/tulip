import re
import unittest

from synth import candidate_anchors, gate_zero_benign, synthesize_regex


class CandidateAnchorsTest(unittest.TestCase):
    def test_filters_short_and_whitespace_and_sorts_desc(self):
        tokens = [b"ab", b"    ", b"", b"GET ", b"/admin/login", b"\t\n"]
        anchors = candidate_anchors(tokens, min_len=4)
        # short (b"ab") and pure-whitespace tokens are dropped
        self.assertNotIn(b"ab", anchors)
        self.assertNotIn(b"    ", anchors)
        self.assertNotIn(b"\t\n", anchors)
        self.assertNotIn(b"", anchors)
        self.assertEqual(anchors, [b"/admin/login", b"GET "])
        # strictly non-increasing length (most specific first)
        lengths = [len(a) for a in anchors]
        self.assertEqual(lengths, sorted(lengths, reverse=True))

    def test_dedup_preserves_membership(self):
        anchors = candidate_anchors([b"token", b"token", b"other"], min_len=4)
        self.assertEqual(sorted(anchors), [b"other", b"token"])
        self.assertEqual(len(anchors), 2)

    def test_min_len_boundary_inclusive(self):
        # length exactly == min_len is kept
        self.assertIn(b"abcd", candidate_anchors([b"abcd"], min_len=4))
        self.assertNotIn(b"abc", candidate_anchors([b"abc"], min_len=4))


class SynthesizeRegexTest(unittest.TestCase):
    def test_picks_attack_token_absent_from_benign(self):
        attack_sample = b"POST /api HTTP/1.1\r\n\r\n;cat /flag/__EXPLOIT__"
        const_tokens = [b"/api", b"__EXPLOIT__", b";cat /flag/"]
        benign_samples = [
            b"POST /api HTTP/1.1\r\n\r\n{\"user\": \"checker\"}",
            b"GET /api/health HTTP/1.1\r\n\r\n",
        ]
        regex = synthesize_regex(const_tokens, benign_samples)
        self.assertIsNotNone(regex)
        # matches the attack, never a benign sample
        self.assertTrue(re.search(regex, attack_sample))
        for benign in benign_samples:
            self.assertIsNone(re.search(regex, benign))
        # output passes its own gate
        self.assertTrue(gate_zero_benign(regex, benign_samples))

    def test_prefers_most_specific_clean_anchor(self):
        # both anchors are benign-clean; the longer one must win
        const_tokens = [b"SHORTTOK", b"VERYLONGEXPLOITMARKER"]
        regex = synthesize_regex(const_tokens, benign_samples=[b"nothing here"])
        self.assertEqual(regex, re.escape(b"VERYLONGEXPLOITMARKER"))

    def test_skips_specific_but_benign_anchor_for_clean_shorter(self):
        # longest token leaks into benign; falls back to the shorter clean one
        const_tokens = [b"COMMON_HEADER_PREFIX", b"PWN!"]
        benign_samples = [b"COMMON_HEADER_PREFIX legitimate request"]
        regex = synthesize_regex(const_tokens, benign_samples)
        self.assertEqual(regex, re.escape(b"PWN!"))
        self.assertTrue(gate_zero_benign(regex, benign_samples))

    def test_returns_none_when_only_distinctive_token_is_in_benign(self):
        # The safety case: the single distinctive token also appears in a
        # benign/checker sample. Emitting a rule would DROP the SLA checker
        # and zero our SLA -- so we MUST refuse.
        const_tokens = [b"/status?id=", b"hi"]  # b"hi" too short to anchor
        benign_samples = [b"GET /status?id=42 from checker"]
        self.assertIsNone(synthesize_regex(const_tokens, benign_samples))

    def test_returns_none_when_all_anchors_in_benign(self):
        const_tokens = [b"alpha_token", b"beta_token", b"gamma_token"]
        benign_samples = [
            b"...alpha_token...",
            b"...beta_token...",
            b"...gamma_token...",
        ]
        self.assertIsNone(synthesize_regex(const_tokens, benign_samples))

    def test_returns_none_when_no_candidate_anchors(self):
        # all tokens filtered out (too short / whitespace) -> nothing to anchor
        self.assertIsNone(synthesize_regex([b"ab", b"   "], benign_samples=[]))

    def test_regex_metachars_are_escaped(self):
        # a token full of regex metacharacters must match literally
        attack_sample = b"payload=a.b*c+(d)|e"
        const_tokens = [b"a.b*c+(d)|e"]
        regex = synthesize_regex(const_tokens, benign_samples=[b"benign abcde"])
        self.assertIsNotNone(regex)
        self.assertTrue(re.search(regex, attack_sample))
        # escaped: does not match the metachar interpretation
        self.assertIsNone(re.search(regex, b"benign abcde"))


class GateZeroBenignTest(unittest.TestCase):
    def test_false_when_regex_matches_a_benign_sample(self):
        regex = re.escape(b"/login")
        benign = [b"GET /home", b"POST /login HTTP/1.1"]
        self.assertFalse(gate_zero_benign(regex, benign))

    def test_true_when_regex_matches_no_benign_sample(self):
        regex = re.escape(b"__EXPLOIT__")
        benign = [b"GET /home", b"POST /login HTTP/1.1"]
        self.assertTrue(gate_zero_benign(regex, benign))

    def test_true_on_empty_benign_set(self):
        self.assertTrue(gate_zero_benign(re.escape(b"anything"), []))


if __name__ == "__main__":
    unittest.main()
