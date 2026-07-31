// Command switchboard is the CLI and daemon entry point.
package main

import (
	"fmt"
	"os"

	"github.com/alsey89/switchboard/internal/cli"
)

func main() {
	if err := cli.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
