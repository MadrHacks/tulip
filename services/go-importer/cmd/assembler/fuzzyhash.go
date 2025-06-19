package main

import (
	"go-importer/internal/pkg/db"

	"github.com/chikamim/nilsimsa"
)

func ComputeFuzzyhash(flow *db.FlowEntry) {
	totalSize := 0
	for _, flowItem := range flow.Flow {
		totalSize += len(flowItem.Data)
	}

	allData := make([]byte, 0, totalSize)
	for _, flowItem := range flow.Flow {
		allData = append(allData, flowItem.Data...)
	}

	flow.Fuzzyhash = nilsimsa.HexSum(allData)
}
