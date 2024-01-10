// landlock-restrict-net executes a process with Landlock network restrictions
//
// This is an example tool which does not provide backwards
// compatibility guarantees.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func usage() {
	var (
		out  = flag.CommandLine.Output()
		name = os.Args[0]
	)
	fmt.Fprintf(out, "Usage of %s:\n", name)
	flag.PrintDefaults()
	fmt.Fprintf(out, "\nExample usages:\n")
	fmt.Fprintf(out, "  %s -tcp.bind 8080 /usr/bin/nc -l 127.0.0.1 8080\n", name)
	fmt.Fprintf(out, "  %s -tcp.connect 8080 /usr/bin/nc 127.0.0.1 8080\n", name)
}

func main() {
	flag.Usage = usage

	var rules []landlock.Rule
	flag.Func("tcp.bind", "A TCP port where bind(2) should be permitted", func(s string) error {
		p, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return err
		}
		log.Println("PERMIT TCP bind on port", p)
		rules = append(rules, landlock.BindTCP(uint16(p)))
		return nil
	})
	flag.Func("tcp.connect", "A TCP port where connect(2) should be permitted", func(s string) error {
		p, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return err
		}
		log.Println("PERMIT TCP connect to port", p)
		rules = append(rules, landlock.ConnectTCP(uint16(p)))
		return nil
	})

	flag.Parse()

	var cmd []string
	if flag.NArg() > 1 {
		cmd = flag.Args()
	} else {
		log.Println("missing command to call, using /bin/bash")
		cmd = []string{"/bin/bash"}
	}

	if err := landlock.V4.RestrictNet(rules...); err != nil {
		log.Fatalf("landlock RestrictNet: %v", err)
	}

	log.Printf("Starting %v", cmd)
	if err := syscall.Exec(cmd[0], cmd, os.Environ()); err != nil {
		log.Fatalf("execve: %v", err)
	}
}
