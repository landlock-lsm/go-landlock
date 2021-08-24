package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func takeArgs(args, out []string) (argsOut, outOut []string) {
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		out = append(out, args[0])
		args = args[1:]
	}
	return args, out
}

func parseFlags(args []string) (verbose bool, roDirs, rwDirs, roFiles, rwFiles, cmd []string) {
	for len(args) > 0 {
		switch args[0] {
		case "-v":
			verbose = true
			args = args[1:]
			continue
		case "-ro":
			args = args[1:]
			args, roDirs = takeArgs(args, roDirs)
			continue
		case "-rw":
			args = args[1:]
			args, rwDirs = takeArgs(args, rwDirs)
			continue
		case "-rofiles":
			args = args[1:]
			args, roFiles = takeArgs(args, roFiles)
			continue
		case "-rwfiles":
			args = args[1:]
			args, rwFiles = takeArgs(args, rwFiles)
			continue
		case "--":
			args = args[1:]
			// Remaining args are the command
			cmd = args
			return verbose, roDirs, rwDirs, roFiles, rwFiles, cmd
		default:
			log.Fatalf("Unrecognized option %q", args[0])
		}
	}

	cmd = args
	return verbose, roDirs, rwDirs, roFiles, rwFiles, cmd
}

func main() {
	verbose, roDirs, rwDirs, roFiles, rwFiles, cmdArgs := parseFlags(os.Args[1:])
	if verbose {
		fmt.Println("Landlock restricting to:")
		fmt.Printf("  RO dirs : %v\n", roDirs)
		fmt.Printf("  RW dirs : %v\n", rwDirs)
		fmt.Printf("  RO files: %v\n", roFiles)
		fmt.Printf("  RW files: %v\n", rwFiles)
		fmt.Println()
		fmt.Printf("Executing command %v\n", cmdArgs)
	}

	if len(cmdArgs) < 1 {
		fmt.Println("Usage:")
		fmt.Println("  landlock-restrict [-ro PATH...] [-rw PATH...] [-rofiles PATH] [-rwfiles PATH] -- COMMAND...")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -ro, -rw, -rofiles, -rwfiles   paths to restrict to")
		fmt.Println("  -verbose                       verbose logging")
		fmt.Println()

		log.Fatalf("Need proper command, got %v", cmdArgs)
	}

	if !strings.HasPrefix(cmdArgs[0], "/") {
		log.Fatalf("Need absolute binary path, got %q", cmdArgs[0])
	}

	err := landlock.V1.BestEffort().RestrictPaths(
		landlock.RODirs(roDirs...),
		landlock.RWDirs(rwDirs...),
		landlock.ROFiles(roFiles...),
		landlock.RWFiles(rwFiles...),
	)
	if err != nil {
		log.Fatalf("landlock: %v", err)
	}

	if err := syscall.Exec(cmdArgs[0], cmdArgs, os.Environ()); err != nil {
		log.Fatalf("execve: %v", err)
	}
}
