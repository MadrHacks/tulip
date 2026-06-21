package main

import (
	"context"
	"log"
	"os"

	"go-importer/internal/pkg/db"
	"go-importer/internal/pkg/mine"
)

func main() {
	timescale := os.Getenv("TIMESCALE")
	if timescale == "" {
		log.Fatalln("minecore: TIMESCALE not set")
	}
	database := db.NewDatabase(timescale)
	mine.New(database, mine.ConfigFromEnv()).Run(context.Background())
}
