package noisecat

import (
	"github.com/gedigi/noise"
	"github.com/gedigi/noisesocket"
)

// NoisesocketConfig is a noisesocket configuration variable
type NoisesocketConfig noisesocket.ConnectionConfig

// GetLocalStaticPublic returns the noisesocket local static key forn
func (n NoisesocketConfig) GetLocalStaticPublic() []byte {
	return n.StaticKeypair.Public
}

func (config *Configuration) parseNoisesocket() (*noisesocket.ConnectionConfig, error) {
	var err error
	_, config.DHFunc, config.CipherFunc, config.HashFunc, err = parseProtocolName(config.Protocol)
	if err != nil {
		return nil, err
	}

	cs := noise.NewCipherSuite(
		DHByteObj[config.DHFunc],
		CipherByteObj[config.CipherFunc],
		HashByteObj[config.HashFunc],
	)
	noiseConf := &noisesocket.ConnectionConfig{
		IsClient:   !config.Listen,
		DHFunc:     config.DHFunc,
		CipherFunc: config.CipherFunc,
		HashFunc:   config.HashFunc,
	}
	noiseConf.StaticKeypair, err = config.checkLocalKeypair(cs)
	if err != nil {
		return nil, err
	}
	return noiseConf, nil
}
