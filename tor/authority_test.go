package tor

import (
	"testing"
)

func TestAuthority_GetOnionRouters(t *testing.T) {
	authority := GetRandomAuthority()
	if authority.Nickname == "" {
		t.Error("No authority found")
		return
	}

	t.Log("Authority:", authority.Nickname)

	onionRouters, err := authority.GetOnionRouters()
	if err != nil {
		t.Error(err)
		return
	}

	if len(onionRouters) < 3 {
		t.Error("No onion routers found")
		return
	}

	t.Log("Onion routers:", len(onionRouters))
	t.Log("Onion router #1:", onionRouters[0].Nickname)
	t.Log("Onion router #2:", onionRouters[1].Nickname)
	t.Log("Onion router #3:", onionRouters[2].Nickname)

	t.Log("Onion router #1 Identity:", onionRouters[0].Identity)
	t.Log("Onion router #1 Flags:", onionRouters[0].Flags)
}
