package main

import (
	"fmt"

	"rotten-onion-tor/tor"
)

func main() {
	client, err := tor.NewClient(3)
	if err != nil {
		panic(err)
	}

	relay := client.GetRandomOnionRelay()
	guard := client.GetRandomGuardRelay()
	exit := client.GetRandomExitRelay()

	fmt.Println("Random Onion Relay:", relay.Nickname)
	fmt.Println("Random Guard Relay:", guard.Nickname)
	fmt.Println("Random Exit Relay:", exit.Nickname)

	nTorKey, err := exit.FetchNTorKey(client.Authority)
	if err != nil {
		panic(err)
	}

	fmt.Println("Random Exit Relay NTorKey:", nTorKey)
}
