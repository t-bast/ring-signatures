// Package main allows you to produce and verify ring signatures.
package main

import (
	"os"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "ring-signatures"
	app.Usage = "generate and verify ring signatures."
	app.Version = "0.1.0"

	app.Run(os.Args)
}
