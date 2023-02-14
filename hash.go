package libtrust

import (
	"crypto"
	_ "crypto/sha256" // Registrer SHA224 and SHA256
	_ "crypto/sha512" // Registrer SHA384 and SHA512
)

type signatureAlgorithm struct {
	algHeaderParam string
	hashID         crypto.Hash
}

func (h *signatureAlgorithm) HeaderParam() string {
	return h.algHeaderParam
}

func (h *signatureAlgorithm) HashID() crypto.Hash {
	return h.hashID
}

var (
	es256 = &signatureAlgorithm{"ES256", crypto.SHA256}
	es384 = &signatureAlgorithm{"ES384", crypto.SHA384}
	es512 = &signatureAlgorithm{"ES512", crypto.SHA512}
)
