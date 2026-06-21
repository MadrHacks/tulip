"""Gated defensive deploy: synthesize a zero-benign-gated regex and push it to
firegex INACTIVE; enabling a rule requires `armed`. Layered safety: synthesis
refuses any anchor seen in benign/checker traffic, rules are created disabled,
and only an armed engine flips them live. Rollback disables + deletes."""

from firegex_client import FiregexClient
from synth import synthesize_regex


def _b(x):
    return x.encode() if isinstance(x, str) else x


class PatchEngine:
    def __init__(self, firegex: FiregexClient, armed: bool = False):
        self.firegex = firegex
        self.armed = armed
        self.deployed: dict[str, int] = {}  # cluster_tag -> regex_id

    def propose(self, cluster_tag, const_tokens, benign_samples, service_id, mode="B"):
        """Synthesize + push a rule for a cluster, INACTIVE. Returns the regex id,
        or None if synthesis refused (no anchor absent from benign traffic)."""
        regex = synthesize_regex([_b(t) for t in const_tokens], [_b(s) for s in benign_samples])
        if regex is None:
            return None
        regex_id = self.firegex.add_regex(service_id, regex, mode=mode, active=False)
        if regex_id is not None:
            self.deployed[cluster_tag] = regex_id
        return regex_id

    def arm_rule(self, cluster_tag):
        """Enable a proposed rule — only when the engine is armed."""
        if not self.armed:
            return False
        regex_id = self.deployed.get(cluster_tag)
        if regex_id is None:
            return False
        return self.firegex.set_regex_active(regex_id, True)

    def rollback(self, cluster_tag):
        """Disable + delete a deployed rule (reflexive on any SLA dip)."""
        regex_id = self.deployed.pop(cluster_tag, None)
        if regex_id is None:
            return False
        self.firegex.set_regex_active(regex_id, False)
        return self.firegex.delete_regex(regex_id)
