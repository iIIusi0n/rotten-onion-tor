package main

import (
	"fmt"
	"rotten-onion-tor/tor"
)

func main() {
	authority := tor.GetRandomAuthority()
	fmt.Println(authority.Nickname)
}
