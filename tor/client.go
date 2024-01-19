package tor

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type Client struct {
	Authority    *Authority
	OnionRouters []OnionRouter

	routersInUsed []string
}

func NewClient(maxAuthorityAttempts int) (*Client, error) {
	var err error

	client := &Client{}

	for i := 0; i < maxAuthorityAttempts; i++ {
		client.Authority = GetRandomAuthority()
		client.OnionRouters, err = client.Authority.GetOnionRouters()
		if err != nil {
			continue
		}

		if len(client.OnionRouters) == 0 {
			continue
		}

		return client, nil
	}

	return nil, errors.New("Failed to download consensus from authorities")
}

func (c *Client) isRouterInUsed(router OnionRouter) bool {
	for _, r := range c.routersInUsed {
		if r == router.Identity {
			return true
		}
	}

	return false
}

func (c *Client) getRandomRouterWithFlag(flag string) *OnionRouter {
	routers := make([]OnionRouter, 0)
	for _, router := range c.OnionRouters {
		if c.isRouterInUsed(router) {
			continue
		}

		if flag == "" {
			routers = append(routers, router)
		} else {
			if router.HasFlag(flag) {
				routers = append(routers, router)
			}
		}
	}

	if len(routers) == 0 {
		return nil
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(routers))))
	if err != nil {
		return nil
	}

	return &routers[n.Int64()]
}

func (c *Client) GetRandomOnionRelay() *OnionRouter {
	return c.getRandomRouterWithFlag("")
}

func (c *Client) GetRandomExitRelay() *OnionRouter {
	return c.getRandomRouterWithFlag("exit")
}

func (c *Client) GetRandomGuardRelay() *OnionRouter {
	return c.getRandomRouterWithFlag("guard")
}
