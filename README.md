# Rotten Onion Tor

Minimal Tor client implementation in Go supporting hidden services.

## Features

- Circuit creation and extension with nTor/nTor-v3 handshake
- Hidden service (onion) connections
- Directory consensus and descriptor parsing
- Introduction and rendezvous protocol

## Installation

```bash
go get rotten-onion-tor
```

## Usage

```go
package main

import (
    "log"
    "os"
    "rotten-onion-tor/pkg/tor"
)

func main() {
    logger := log.New(os.Stdout, "", log.Ltime)
    client, err := tor.NewClient(logger)
    if err != nil {
        log.Fatal(err)
    }

    body, err := client.HTTPGetOnion("https://example.onion/")
    if err != nil {
        log.Fatal(err)
    }

    println(body)
}
```

## Example

```bash
go run cmd/torclient/main.go
```

## Structure

```
pkg/
├── cell/       Cell encoding/decoding
├── channel/    TLS channel management
├── circuit/    Circuit creation and relay
├── crypto/     nTor handshake and stream cipher
├── directory/  Consensus parsing and router selection
├── onion/      Hidden service protocol
├── stream/     TCP-like stream over circuits
└── tor/        High-level client API
```

## References

- [Tor Specifications](https://github.com/torproject/torspec)
- [mini-tor](https://github.com/wbenny/mini-tor)
- [Arti](https://gitlab.torproject.org/tpo/core/arti)
