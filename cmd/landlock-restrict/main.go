package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/gnoack/golandlock"
)

func parseFlags(args []string) (verbose bool, ro, rw, cmd []string) {
	for len(args) > 0 {
		switch args[0] {
		case "-v":
			verbose = true
			args = args[1:]
			continue
		case "-ro":
			args = args[1:]
			for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
				ro = append(ro, args[0])
				args = args[1:]
			}
			continue
		case "-rw":
			args = args[1:]
			for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
				rw = append(rw, args[0])
				args = args[1:]
			}
			continue
		case "--":
			args = args[1:]
			// Remaining args are the command
			cmd = args
			return verbose, ro, rw, cmd
		default:
			log.Fatalf("Unrecognized option %q", args[0])
		}
	}

	cmd = args
	return verbose, ro, rw, cmd
}

func main() {
	verbose, roPaths, rwPaths, cmdArgs := parseFlags(os.Args[1:])
	if verbose {
		fmt.Println("Landlock restricting to:")
		fmt.Printf("  RO paths: %v\n", roPaths)
		fmt.Printf("  RW paths: %v\n", rwPaths)
		fmt.Println()
		fmt.Printf("Executing command %v\n", cmdArgs)
	}

	if len(cmdArgs) < 1 {
		log.Fatalf("Need proper command, got %v", cmdArgs)
	}

	if !strings.HasPrefix(cmdArgs[0], "/") {
		log.Fatalf("Need absolute binary path, got %q", cmdArgs[0])
	}

	err := golandlock.V1.BestEffort().RestrictPaths(
		golandlock.RODirs(roPaths...),
		golandlock.RWDirs(rwPaths...),
	)
	if err != nil {
		log.Fatalf("landlock: %v", err)
	}

	if err := syscall.Exec(cmdArgs[0], cmdArgs, os.Environ()); err != nil {
		log.Fatalf("execve: %v", err)
	}
}
