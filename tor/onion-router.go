package tor

type OnionRouter struct {
	Nickname string
	Identity string
	Digest   string
	IP       string
	OrPort   int
	DirPort  int

	Flags   []string
	NTorKey string
}

func NewOnionRouter(nickname, identity, digest, ip string, orPort, dirPort int, flags []string, nTorKey string) *OnionRouter {
	return &OnionRouter{
		nickname,
		identity,
		digest,
		ip,
		orPort,
		dirPort,
		flags,
		nTorKey,
	}
}

func NewOnionRouterWithoutDetail(nickname, identity, digest, ip string, orPort, dirPort int) *OnionRouter {
	return NewOnionRouter(nickname, identity, digest, ip, orPort, dirPort, nil, "")
}

func (o *OnionRouter) UpdateNTorKey(authority *Authority) error {
	nTorKey, err := authority.GetOnionRouterNTorKey(o)
	if err != nil {
		return err
	}

	o.NTorKey = nTorKey
	return nil
}

func (o *OnionRouter) HasFlag(flag string) bool {
	for _, f := range o.Flags {
		if f == flag {
			return true
		}
	}

	return false
}
