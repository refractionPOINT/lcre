package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version and BuildTime are set via ldflags at build time.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print LCRE version and build info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("lcre %s (built %s)\n", Version, BuildTime)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
