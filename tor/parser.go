package tor

import (
	"log"
	"strconv"
	"strings"

	"rotten-onion-tor/utils"
)

func isValidFlags(flags []string) bool {
	flagMap := make(map[string]bool)

	for _, flag := range flags {
		flagMap[flag] = true
	}

	if flagMap["stable"] && flagMap["fast"] && flagMap["valid"] && flagMap["running"] {
		return true
	} else {
		return false
	}
}

func parseConsensus(content string) ([]OnionRouter, error) {
	log.Println("Parsing consensus")

	onionRouters := make([]OnionRouter, 0)
	onionRouterCount := 0
	onionRouterLimit := 300

	lastOnionRouter := OnionRouter{}

	lines := strings.Split(content, "\n")
	log.Println("Consensus lines:", len(lines))

	for _, line := range lines {
		if strings.HasPrefix(line, "r ") {
			splitted := strings.Split(line, " ")

			nickname := splitted[1]
			identity := splitted[2]
			digest := splitted[3]
			ip := splitted[6]
			orPort, err := strconv.Atoi(splitted[7])
			dirPort, err := strconv.Atoi(splitted[8])
			if err != nil {
				log.Fatalln(err)

				return nil, err
			}

			identity += strings.Repeat("=", 4-len(identity)%4)
			identity = utils.Base64ToHex(identity)

			lastOnionRouter = *NewOnionRouterWithoutDetail(nickname, identity, digest, ip, orPort, dirPort)
		} else if strings.HasPrefix(line, "s ") {
			if lastOnionRouter.Nickname == "" {
				continue
			}

			splitted := strings.Split(line, " ")
			for _, flag := range splitted[1:] {
				trimmedFlag := strings.ToLower(strings.TrimSpace(flag))
				lastOnionRouter.Flags = append(lastOnionRouter.Flags, trimmedFlag)
			}

			if isValidFlags(lastOnionRouter.Flags) {
				onionRouters = append(onionRouters, lastOnionRouter)
				onionRouterCount++
			}
		}

		if onionRouterCount >= onionRouterLimit {
			break
		}
	}

	log.Println("Parsed onion routers:", len(onionRouters))

	return onionRouters, nil
}

func parseRouterDescriptor(content string) (string, error) {
	log.Println("Parsing router descriptor")

	lines := strings.Split(content, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "ntor-onion-key ") {
			splitted := strings.Split(line, " ")

			nTorKey := splitted[1]
			nTorKey += strings.Repeat("=", 4-len(nTorKey)%4)

			return nTorKey, nil
		}
	}

	return "", nil
}
