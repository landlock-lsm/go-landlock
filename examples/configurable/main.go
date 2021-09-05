package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

var (
	cfgFile = flag.String("cfg_file", "", "config file (JSON)")
)

type PathException struct {
	Paths           []string `json:"paths"`
	PermittedAccess []string `json:"permitted_access"`
}

type Config struct {
	ForbiddenAccess []string        `json:"forbidden_access"`
	Exceptions      []PathException `json:"exceptions"`
	BestEffort      bool            `json:"best_effort"`
}

func main() {
	flag.Parse()

	// Read configuration file.
	buf, err := os.ReadFile(*cfgFile)
	if err != nil {
		log.Fatalf("io.ReadAll: %v", err)
	}

	var jsonCfg Config
	err = json.Unmarshal(buf, &jsonCfg)
	if err != nil {
		log.Fatalf("json.Unmarshal: %v", err)
	}

	// Print config for debugging.
	b, err := json.MarshalIndent(jsonCfg, "", "  ")
	if err != nil {
		log.Fatalf("json.MarshalIndent: %v", err)
	}
	fmt.Println("JSON config:")
	fmt.Println(string(b))

	// Build Landlock config.
	forbiddenAccess := accessFSSet(jsonCfg.ForbiddenAccess)
	cfg, err := landlock.NewConfig(forbiddenAccess)
	if err != nil {
		log.Fatalf("landlock.NewConfig: %v", err)
	}
	if jsonCfg.BestEffort {
		cfg2 := cfg.BestEffort()
		cfg = &cfg2
	}

	// Enforce.
	err = cfg.RestrictPaths(exceptions(jsonCfg.Exceptions)...)
	if err != nil {
		log.Fatalf("RestrictPaths: %v", err)
	}

	// Run an executable.
	executable := "/bin/bash"

	os.Chdir("/")
	cmd := exec.Command(executable)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("execve: %v", err)
	}
}

func accessFSSet(names []string) (a landlock.AccessFSSet) {
	var table = map[string]landlock.AccessFSSet{
		"execute":     llsys.AccessFSExecute,
		"write_file":  llsys.AccessFSWriteFile,
		"read_file":   llsys.AccessFSReadFile,
		"read_dir":    llsys.AccessFSReadDir,
		"remove_dir":  llsys.AccessFSRemoveDir,
		"remove_file": llsys.AccessFSRemoveFile,
		"make_char":   llsys.AccessFSMakeChar,
		"make_dir":    llsys.AccessFSMakeDir,
		"make_reg":    llsys.AccessFSMakeReg,
		"make_sock":   llsys.AccessFSMakeSock,
		"make_fifo":   llsys.AccessFSMakeFifo,
		"make_block":  llsys.AccessFSMakeBlock,
		"make_sym":    llsys.AccessFSMakeSym,
	}
	for _, n := range names {
		x, ok := table[n]
		if !ok {
			log.Fatalf("unknown access fs flag %q", n)
		}
		a |= x
	}
	return a
}

func exceptions(es []PathException) (opts []landlock.PathOpt) {
	for _, e := range es {
		permittedAccess := accessFSSet(e.PermittedAccess)
		po := landlock.PathAccess(permittedAccess, e.Paths...)
		opts = append(opts, po)
	}
	return opts
}
