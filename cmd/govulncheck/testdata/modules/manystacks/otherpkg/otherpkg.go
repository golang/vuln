package otherpkg

import "github.com/shiyanhui/dht"

func GetPeers(d *dht.DHT, s string) error {
	return d.GetPeers(s)
}
