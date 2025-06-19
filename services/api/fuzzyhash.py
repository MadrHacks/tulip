#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from cnilsimsa import compare_hexdigests
import database


def fuzzyhash_filter_flows(flows, similarity, include_set, exclude_set):
	if not include_set and not exclude_set:
		return flows

	# adapt similarity to nilsimsa compare value
	similarity_nilsisma = (similarity * 256 / 100) - 128

	filtered_flows = []
	for flow in flows:
		include_sims = tuple(compare_hexdigests(flow["fuzzyhash"], h) for h in include_set)
		if any(s < similarity_nilsisma for s in include_sims):
			continue

		exclude_sims = tuple(compare_hexdigests(flow["fuzzyhash"], h) for h in exclude_set)
		if any(s >= similarity_nilsisma for s in exclude_sims):
			continue

		sim, n_set = 0, 0
		if include_sims:
			avg_include_sim = (128 + (sum(include_sims) / len(include_sims))) / 256
			sim += avg_include_sim
			n_set += 1

		if exclude_sims:
			avg_exclude_sim = (128 - (sum(exclude_sims) / len(exclude_sims))) / 256
			sim += avg_exclude_sim
			n_set += 1

		if n_set:
			flow['similarity'] = sim / n_set

		filtered_flows.append(flow)

	return filtered_flows