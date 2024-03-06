package tor

type OnionRouter struct {
	Nickname string
	Identity string
	Digest   string
	IP       string
	OrPort   int
	DirPort  int

	Flags []string
}

func NewOnionRouter(nickname, identity, digest, ip string, orPort, dirPort int, flags []string) *OnionRouter {
	return &OnionRouter{
		nickname,
		identity,
		digest,
		ip,
		orPort,
		dirPort,
		flags,
	}
}

func NewOnionRouterWithoutDetail(nickname, identity, digest, ip string, orPort, dirPort int) *OnionRouter {
	return NewOnionRouter(nickname, identity, digest, ip, orPort, dirPort, nil)
}

func (o *OnionRouter) FetchNTorKey(authority *Authority) (string, error) {
	nTorKey, err := authority.GetOnionRouterNTorKey(o)
	if err != nil {
		return "", err
	}

	return nTorKey, nil
}

func (o *OnionRouter) HasFlag(flag string) bool {
	for _, f := range o.Flags {
		if f == flag {
			return true
		}
	}

	return false
}
