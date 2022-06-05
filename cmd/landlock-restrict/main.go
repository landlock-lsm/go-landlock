package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)


func parseFlags(args []string) (verbose bool, cfg landlock.Config, opts []landlock.PathOpt, cmd []string) {
	cfg = landlock.V2

	takeArgs := func(makeOpt func(...string) landlock.PathOpt) landlock.PathOpt {
		var paths []string
		needRefer := false
		for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			if args[0] == "+refer" {
				needRefer = true
			} else {
				paths = append(paths, args[0])
			}
			args = args[1:]
		}
		opt := makeOpt(paths...)
		if verbose {
			fmt.Println("Path option:", opt)
		}
		if needRefer {
			opt = opt.WithRefer()
		}
		if verbose {
			fmt.Println("Path option:", opt)
		}
		return opt
	}

	bestEffort := true
ArgParsing:
	for len(args) > 0 {
		switch args[0] {
		case "-2":
			cfg = landlock.V2
			args = args[1:]
			continue
		case "-1":
			cfg = landlock.V1
			args = args[1:]
			continue
		case "-strict":
			bestEffort=false
			args = args[1:]
			continue
		case "-v":
			verbose = true
			args = args[1:]
			continue
		case "-ro":
			args = args[1:]
			opts = append(opts, takeArgs(landlock.RODirs))
			continue
		case "-rw":
			args = args[1:]
			opts = append(opts, takeArgs(landlock.RWDirs))
			continue
		case "-rofiles":
			args = args[1:]
			opts = append(opts, takeArgs(landlock.ROFiles))
			continue
		case "-rwfiles":
			args = args[1:]
			opts = append(opts, takeArgs(landlock.RWFiles))
			continue
		case "--":
			args = args[1:]
			// Remaining args are the command
			break ArgParsing
		default:
			log.Fatalf("Unrecognized option %q", args[0])
		}
	}

	cmd = args
	if bestEffort {
		cfg = cfg.BestEffort()
	}
	return verbose, cfg, opts, cmd
}

func main() {
	verbose, cfg, opts, cmdArgs := parseFlags(os.Args[1:])
	if verbose {
		fmt.Println("Args: ", os.Args)
		fmt.Println()
		fmt.Printf("Config: %v\n", cfg)
		fmt.Println()
		fmt.Printf("Executing command %v\n", cmdArgs)
	}

	if len(cmdArgs) < 1 {
		fmt.Println("Usage:")
		fmt.Println("  landlock-restrict")
		fmt.Println("     [-verbose]")
		fmt.Println("     [-1] [-2] [-strict]")
		fmt.Println("     [-ro [+refer] PATH...] [-rw [+refer] PATH...]")
		fmt.Println("     [-rofiles [+refer] PATH] [-rwfiles [+refer] PATH]")
		fmt.Println("       -- COMMAND...")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -ro, -rw, -rofiles, -rwfiles   paths to restrict to")
		fmt.Println("  -1, -2                         select Landlock version")
		fmt.Println("  -strict                        use strict mode (instead of best effort)")
		fmt.Println("  -verbose                       verbose logging")
		fmt.Println()
		fmt.Println("A path list that contains the word '+refer' will additionally grant the refer access right.")
		fmt.Println()
		fmt.Println("Default mode for Landlock is V2 in best effort mode (best compatibility)")
		fmt.Println()

		log.Fatalf("Need proper command, got %v", cmdArgs)
	}

	if !strings.HasPrefix(cmdArgs[0], "/") {
		log.Fatalf("Need absolute binary path, got %q", cmdArgs[0])
	}

	err := cfg.RestrictPaths(opts...)
	if err != nil {
		log.Fatalf("landlock: %v", err)
	}

	if err := syscall.Exec(cmdArgs[0], cmdArgs, os.Environ()); err != nil {
		log.Fatalf("execve: %v", err)
	}
}
