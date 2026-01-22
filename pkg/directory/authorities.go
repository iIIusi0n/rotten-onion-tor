// Package directory implements Tor directory operations including
// fetching consensus documents and parsing relay information.
package directory

// DirectoryAuthority represents a Tor directory authority server.
type DirectoryAuthority struct {
	Name        string
	Address     string
	DirPort     int
	ORPort      int
	V3Ident     string // hex-encoded v3 identity key fingerprint
	Fingerprint string // hex-encoded RSA identity fingerprint
}

// DefaultAuthorities returns the hardcoded list of Tor directory authorities.
// These are taken from the Tor source code (auth_dirs.inc).
var DefaultAuthorities = []DirectoryAuthority{
	{
		Name:        "moria1",
		Address:     "128.31.0.39",
		DirPort:     9231,
		ORPort:      9201,
		V3Ident:     "F533C81CEF0BC0267857C99B2F471ADF249FA232",
		Fingerprint: "1A25C6358DB91342AA51720A5038B72742732498",
	},
	{
		Name:        "tor26",
		Address:     "217.196.147.77",
		DirPort:     80,
		ORPort:      443,
		V3Ident:     "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C",
		Fingerprint: "FAA4BCA4A6AC0FB4CA2F8AD5A11D9E122BA894F6",
	},
	{
		Name:        "dizum",
		Address:     "45.66.35.11",
		DirPort:     80,
		ORPort:      443,
		V3Ident:     "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
		Fingerprint: "7EA6EAD6FD83083C538F44038BBFA077587DD755",
	},
	{
		Name:        "gabelmoo",
		Address:     "131.188.40.189",
		DirPort:     80,
		ORPort:      443,
		V3Ident:     "ED03BB616EB2F60BEC80151114BB25CEF515B226",
		Fingerprint: "F2044413DAC2E02E3D6BCF4735A19BCA1DE97281",
	},
	{
		Name:        "dannenberg",
		Address:     "193.23.244.244",
		DirPort:     80,
		ORPort:      443,
		V3Ident:     "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
		Fingerprint: "7BE683E65D48141321C5ED92F075C55364AC7123",
	},
	{
		Name:        "maatuska",
		Address:     "171.25.193.9",
		DirPort:     443,
		ORPort:      80,
		V3Ident:     "49015F787433103580E3B66A1707A00E60F2D15B",
		Fingerprint: "BD6A829255CB08E66FBE7D3748363586E46B3810",
	},
	{
		Name:        "longclaw",
		Address:     "199.58.81.140",
		DirPort:     80,
		ORPort:      443,
		V3Ident:     "23D15D965BC35114467363C165C4F724B64B4F66",
		Fingerprint: "74A910646BCEEFBCD2E874FC1DC997430F968145",
	},
	{
		Name:        "bastet",
		Address:     "204.13.164.118",
		DirPort:     80,
		ORPort:      443,
		V3Ident:     "27102BC123E7AF1D4741AE047E160C91ADC76B21",
		Fingerprint: "24E2F139121D4394C54B5BCC368B3B411857C413",
	},
	{
		Name:        "faravahar",
		Address:     "216.218.219.41",
		DirPort:     80,
		ORPort:      443,
		V3Ident:     "70849B868D606BAECFB6128C5E3D782029AA394F",
		Fingerprint: "E3E42D35F801C9D5AB23584E0025D56FE2B33396",
	},
}
