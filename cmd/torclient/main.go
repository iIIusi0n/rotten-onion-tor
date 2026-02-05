package main

import (
	"fmt"
	"log"
	"os"

	"rotten-onion-tor/pkg/tor"
)

const duckduckgoOnion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

func main() {
	logger := log.New(os.Stdout, "", log.Ltime)

	client, err := tor.NewClient(logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create client: %v\n", err)
		os.Exit(1)
	}

	body, err := client.HTTPGetOnion("https://" + duckduckgoOnion + "/")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch onion: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(body[:min(len(body), 500)])
}
