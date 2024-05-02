//go:build libtrust_openssl && !go1.22
// +build libtrust_openssl,!go1.22

package libtrust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"
)

func (k *ecPrivateKey) sign(data io.Reader, hashID crypto.Hash) (signature []byte, err error) {
	hId := k.signatureAlgorithm.HashID()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(data)
	if err != nil {
		return nil, fmt.Errorf("error reading data: %s", err)
	}

	r, s, err := ecdsa.HashSign(rand.Reader, k.PrivateKey, buf.Bytes(), hId)
	if err != nil {
		return nil, fmt.Errorf("error producing signature: %s", err)
	}

	rBytes, sBytes := r.Bytes(), s.Bytes()
	octetLength := (k.ecPublicKey.Params().BitSize + 7) >> 3
	// MUST include leading zeros in the output
	rBuf := make([]byte, octetLength-len(rBytes), octetLength)
	sBuf := make([]byte, octetLength-len(sBytes), octetLength)

	rBuf = append(rBuf, rBytes...)
	sBuf = append(sBuf, sBytes...)

	signature = append(rBuf, sBuf...)

	return signature, err
}
