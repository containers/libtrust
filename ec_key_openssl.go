//go:build libtrust_openssl && go1.22
// +build libtrust_openssl,go1.22

package libtrust

import (
	"bytes"
	"crypto"
	"fmt"
	"io"

	openssl "github.com/golang-fips/openssl/v2"
	"github.com/golang-fips/openssl/v2/bbig"
)

func (k *ecPrivateKey) sign(data io.Reader, hashID crypto.Hash) (signature []byte, err error) {
	hId := k.signatureAlgorithm.HashID()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(data)
	if err != nil {
		return nil, fmt.Errorf("reading data to be signed: %s", err)
	}
	x, y, d := bbig.Enc(k.ecPublicKey.X), bbig.Enc(k.ecPublicKey.Y), bbig.Enc(k.PrivateKey.D)
	privateKey, err := openssl.NewPrivateKeyECDSA(k.curveName, x, y, d)
	if err != nil {
		return nil, fmt.Errorf("importing key: %w", err)
	}
	return openssl.HashSignECDSA(privateKey, hId, buf.Bytes())
}
