package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/maxime/lcre/internal/cache"
	"github.com/spf13/cobra"
)

var (
	maxDepth int
)

var queryCallPathCmd = &cobra.Command{
	Use:   "call-path <binary> <from> <to>",
	Short: "Find call path between functions",
	Long:  "Find a call path between two functions using BFS. Requires deep analysis.",
	Args:  cobra.ExactArgs(3),
	RunE:  runQueryCallPath,
}

func init() {
	queryCallPathCmd.Flags().IntVar(&maxDepth, "max-depth", 10, "Maximum path depth to search")
	queryCmd.AddCommand(queryCallPathCmd)
}

type CallPathOutput struct {
	From   string       `json:"from"`
	To     string       `json:"to"`
	Paths  [][]PathNode `json:"paths"`
	Count  int          `json:"count"`
}

type PathNode struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

func runQueryCallPath(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binaryPath := args[0]
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return err
	}

	fromFunc := args[1]
	toFunc := args[2]

	_, db, _, err := ensureAnalyzed(ctx, absPath, queryDeep)
	if err != nil {
		return err
	}
	defer db.Close()

	// Get the source and target functions
	from, err := db.GetFunction(fromFunc)
	if err != nil {
		return err
	}
	if from == nil {
		if outputFormat == "json" {
			fmt.Printf(`{"error": "source function not found: %s"}`+"\n", fromFunc)
		} else {
			fmt.Printf("Source function not found: %s\n", fromFunc)
		}
		return nil
	}

	to, err := db.GetFunction(toFunc)
	if err != nil {
		return err
	}
	if to == nil {
		if outputFormat == "json" {
			fmt.Printf(`{"error": "target function not found: %s"}`+"\n", toFunc)
		} else {
			fmt.Printf("Target function not found: %s\n", toFunc)
		}
		return nil
	}

	// BFS to find paths
	paths := findCallPaths(db, from.Address, to.Address, maxDepth)

	output := CallPathOutput{
		From:  from.Name,
		To:    to.Name,
		Paths: paths,
		Count: len(paths),
	}

	if outputFormat == "json" {
		outputJSON(output)
	} else {
		printCallPathMarkdown(output)
	}

	return nil
}

// findCallPaths uses BFS to find call paths between two functions.
func findCallPaths(db *cache.DB, fromAddr, toAddr uint64, maxDepth int) [][]PathNode {
	var paths [][]PathNode

	// BFS state
	type state struct {
		addr uint64
		path []PathNode
	}

	queue := []state{{addr: fromAddr, path: nil}}
	visited := make(map[uint64]bool)

	// Get function name helper
	getName := func(addr uint64) string {
		f, _ := db.GetFunction(formatAddress(int64(addr)))
		if f != nil {
			return f.Name
		}
		return formatAddress(int64(addr))
	}

	// Add starting node
	startPath := []PathNode{{
		Name:    getName(fromAddr),
		Address: formatAddress(int64(fromAddr)),
	}}
	queue[0].path = startPath

	for len(queue) > 0 && len(paths) < 5 { // Limit to 5 paths
		current := queue[0]
		queue = queue[1:]

		if len(current.path) > maxDepth {
			continue
		}

		if current.addr == toAddr {
			paths = append(paths, current.path)
			continue
		}

		if visited[current.addr] {
			continue
		}
		visited[current.addr] = true

		// Get callees
		callees, err := db.GetCallees(int64(current.addr))
		if err != nil {
			continue
		}

		for _, callee := range callees {
			if visited[callee.Address] {
				continue
			}

			newPath := make([]PathNode, len(current.path), len(current.path)+1)
			copy(newPath, current.path)
			newPath = append(newPath, PathNode{
				Name:    callee.Name,
				Address: formatAddress(int64(callee.Address)),
			})

			queue = append(queue, state{
				addr: callee.Address,
				path: newPath,
			})
		}
	}

	return paths
}

func printCallPathMarkdown(c CallPathOutput) {
	fmt.Printf("# Call Path: %s -> %s\n\n", c.From, c.To)

	if c.Count == 0 {
		fmt.Println("No path found between the functions.")
		return
	}

	fmt.Printf("Found %d path(s):\n\n", c.Count)

	for i, path := range c.Paths {
		fmt.Printf("## Path %d\n", i+1)
		for j, node := range path {
			indent := ""
			for range j {
				indent += "  "
			}
			if j < len(path)-1 {
				fmt.Printf("%s-> %s (%s)\n", indent, node.Name, node.Address)
			} else {
				fmt.Printf("%s-> **%s** (%s)\n", indent, node.Name, node.Address)
			}
		}
		fmt.Println()
	}
}
