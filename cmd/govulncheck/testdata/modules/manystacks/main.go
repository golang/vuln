// This program prints peers in a bittorrent DHT.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"example.com/manystacks/otherpkg"

	"github.com/shiyanhui/dht"
)

func main() {
	d := dht.New(nil)
	nPeers := 0
	d.OnGetPeersResponse = func(infoHash string, peer *dht.Peer) {
		fmt.Printf("GOT PEER: <%s:%d>\n", peer.IP, peer.Port)
		nPeers++
		if nPeers >= 10 {
			fmt.Printf("Done.\n")
			os.Exit(0)
		}
	}

	go func() {
		for {
			// ubuntu-14.04.2-desktop-amd64.iso
			err := otherpkg.GetPeers(d, "546cf15f724d19c4319cc17b179d7e035f89c1f4")
			if err != nil && err != dht.ErrNotReady {
				log.Fatal(err)
			}

			if err == dht.ErrNotReady {
				time.Sleep(time.Second * 1)
				continue
			}

			break
		}
	}()

	d.Run()
}
