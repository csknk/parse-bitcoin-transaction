package main

import (
	"log"
	"os"

	"github.com/csknk/parse-bitcoin-transaction/cmd/txparser/cmd"
)

func main() {
	cmd := cmd.NewRootCmd()
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
