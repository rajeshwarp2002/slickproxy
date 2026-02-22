package viprox

import (
	"encoding/json"
	"strings"
)

type EndpointConfig struct {
	Endpoints map[string]*Endpoint `json:"-"`
}

func (ec *EndpointConfig) UnmarshalJSON(data []byte) error {
	type temp struct {
		Endpoints []Endpoint `json:"endpoints"`
	}
	var t temp
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}
	ec.Endpoints = make(map[string]*Endpoint)
	for i := range t.Endpoints {

		ec.Endpoints[strings.ToLower(t.Endpoints[i].Endpoint)] = &t.Endpoints[i]
	}
	return nil
}

type Endpoint struct {
	Endpoint string   `json:"endpoint"`
	Port     string   `json:"port"`
	Prefixes []string `json:"prefixes"`
	Peers    []Peer   `json:"peers"`
}

type Peer struct {
	Addr  string   `json:"addr"`
	RP    string   `json:"rp"`
	PC    string   `json:"pc"`
	Ports []string `json:"ports"`
}

func (p *Peer) GetAllPorts() string {
	return strings.Join(p.Ports, ",")
}
