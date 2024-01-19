package tor

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"rotten-onion-tor/utils"
)

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

type Authority struct {
	Nickname string
	IP       string
	Port     int
}

func NewAuthority(nickname, ip string, port int) *Authority {
	return &Authority{
		nickname,
		ip,
		port,
	}
}

func (a *Authority) getConsensusURL() string {
	return fmt.Sprintf("http://%s:%d/tor/status-vote/current/consensus", a.IP, a.Port)
}

func (a *Authority) getConsensusContent() (string, error) {
	url := a.getConsensusURL()

	return utils.DownloadStringFromURL(url)
}
