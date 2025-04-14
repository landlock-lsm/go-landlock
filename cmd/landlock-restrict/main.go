package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func parseFlags(args []string) (verbose bool, cfg landlock.Config, opts []landlock.Rule, cmd []string) {
	cfg = landlock.V5

	takeArgs := func(makeOpt func(...string) landlock.FSRule) landlock.Rule {
		var paths []string
		needRefer := false
		needIoctlDev := false
		for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			switch args[0] {
			case "+refer":
				needRefer = true
			case "+ioctl_dev":
				needIoctlDev = true
			default:
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
		if needIoctlDev {
			opt = opt.WithIoctlDev()
		}
		if verbose {
			fmt.Println("Path option:", opt)
		}
		return opt
	}

	bestEffort := true
	auditCfg := landlock.AuditConfig{}
ArgParsing:
	for len(args) > 0 {
		switch args[0] {
		case "-5":
			cfg = landlock.V5
			args = args[1:]
			continue
		case "-4":
			cfg = landlock.V4
			args = args[1:]
			continue
		case "-3":
			cfg = landlock.V3
			args = args[1:]
			continue
		case "-2":
			cfg = landlock.V2
			args = args[1:]
			continue
		case "-1":
			cfg = landlock.V1
			args = args[1:]
			continue
		case "-strict":
			bestEffort = false
			args = args[1:]
			continue
		case "-audit":
			auditCfg.NewExecutions = true
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
	cfg = cfg.Audit(auditCfg)
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
		fmt.Println("     [-v]")
		fmt.Println("     [-1] [-2] [-3] [-4] [-5] [-strict]")
		fmt.Println("     [-ro [+refer] PATH...] [-rw [+refer] [+ioctl_dev] PATH...]")
		fmt.Println("     [-rofiles [+refer] PATH] [-rwfiles [+refer] PATH]")
		fmt.Println("       -- COMMAND...")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -ro, -rw, -rofiles, -rwfiles   paths to restrict to")
		fmt.Println("  -1, -2, -3, -4, -5             select Landlock version")
		fmt.Println("  -strict                        use strict mode (instead of best effort)")
		fmt.Println("  -v                             verbose logging")
		fmt.Println("  -audit                         enable denial logging in audit for the child process")
		fmt.Println()
		fmt.Println("A path list that contains the word '+refer' will additionally grant the refer access right.")
		fmt.Println()
		fmt.Println("Default mode for Landlock is V5 in best effort mode (best compatibility)")
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
