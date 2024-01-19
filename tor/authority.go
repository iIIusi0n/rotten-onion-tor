package tor

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"rotten-onion-tor/utils"
)

type Authority struct {
	Nickname string
	IP       string
	DirPort  int
}

func NewAuthority(nickname, ip string, dirPort int) *Authority {
	return &Authority{
		nickname,
		ip,
		dirPort,
	}
}

func (a *Authority) getConsensusURL() string {
	return fmt.Sprintf("http://%s:%d/tor/status-vote/current/consensus", a.IP, a.DirPort)
}

func (a *Authority) getConsensusContent() (string, error) {
	log.Println("Downloading consensus from", a.Nickname)

	url := a.getConsensusURL()

	log.Println("Consensus URL:", url)

	return utils.DownloadStringFromURL(url)
}

func (a *Authority) GetOnionRouters() ([]OnionRouter, error) {
	content, err := a.getConsensusContent()
	if err != nil {
		log.Fatalln(err)

		return nil, err
	}

	log.Println("Consensus length:", len(content))

	return parseConsensus(content)
}

func (a *Authority) getRouterDescriptorURL(router *OnionRouter) string {
	return fmt.Sprintf("http://%s:%d/tor/server/fp/%s", a.IP, a.DirPort, router.Identity)
}

func (a *Authority) getRouterDescriptorContent(router *OnionRouter) (string, error) {
	url := a.getRouterDescriptorURL(router)

	return utils.DownloadStringFromURL(url)
}

func (a *Authority) GetOnionRouterNTorKey(router *OnionRouter) (string, error) {
	content, err := a.getRouterDescriptorContent(router)
	if err != nil {
		log.Fatalln(err)

		return "", err
	}

	return parseRouterDescriptor(content)
}

var (
	Authorities = []Authority{
		*NewAuthority("dannenberg", "193.23.244.244", 80),
		*NewAuthority("Serge", "66.111.2.131", 9030),
		*NewAuthority("dizum", "45.66.35.11", 80),
		*NewAuthority("tor26", "86.59.21.38", 80),
		*NewAuthority("bastet", "204.13.164.118", 80),
		*NewAuthority("maatuska", "171.25.193.9", 443),
		*NewAuthority("moria1", "128.31.0.39", 9231),
		*NewAuthority("gabelmoo", "131.188.40.189", 80),
		*NewAuthority("longclaw", "199.58.81.140", 80),
	}
)

func GetRandomAuthority() *Authority {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(Authorities))))
	if err != nil {
		panic(err)
	}

	return &Authorities[n.Int64()]
}
