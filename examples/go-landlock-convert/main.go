// Command convert implements a landlocked image converter.
//
// Usage:
// ./convert < input.jpeg > output.png
//
// This is a basic command line utility that reads from stdin and
// writes to stdout. It has no business opening any additional files,
// so we forbid it with a Landlock policy. Security issues in media
// parsing libraries should not let the attacker access the file
// system.
package main

import (
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"log"
	"os"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func main() {
	if err := landlock.V6.BestEffort().Restrict(); err != nil {
		log.Fatal("Could not enable Landlock:", err)
	}

	imgData, _, err := image.Decode(os.Stdin)
	if err != nil {
		log.Fatal("Could not read input:", err)
	}

	if err := png.Encode(os.Stdout, imgData); err != nil {
		log.Fatal("Could not write output:", err)
	}
}
