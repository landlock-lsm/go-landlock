package main

import (
	"fmt"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func main() {
	v, err := ll.LandlockGetABIVersion()
	if err != nil {
		fmt.Println("0")
	} else { // success
		fmt.Println(v)
	}
}
