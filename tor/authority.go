package tor

import (
	"fmt"
	"rotten-onion-tor/utils"
)

type Authority struct {
	Nickname string
	Host     string
	Port     int
}

func NewAuthority(nickname, host string, port int) *Authority {
	return &Authority{
		nickname,
		host,
		port,
	}
}

func (a *Authority) getConsensusURL() string {
	return fmt.Sprintf("http://%s:%d/tor/status-vote/current/consensus", a.Host, a.Port)
}

func (a *Authority) getConsensusContent() (string, error) {
	url := a.getConsensusURL()

	return utils.DownloadStringFromURL(url)
}
