package libtrust

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
)

/*
 * RSA DSA PUBLIC KEY
 */

// rsaPublicKey implements a JWK Public Key using RSA digital signature algorithms.
type rsaPublicKey struct {
	*rsa.PublicKey
	extended map[string]interface{}
}

// KeyType returns the JWK key type for RSA keys, i.e., "RSA".
func (k *rsaPublicKey) KeyType() string {
	return "RSA"
}

// KeyID returns a distinct identifier which is unique to this Public Key.
func (k *rsaPublicKey) KeyID() string {
	return keyIDFromCryptoKey(k)
}

// CryptoPublicKey returns the internal object which can be used as a
// crypto.PublicKey for use with other standard library operations. The type
// is either *rsa.PublicKey or *ecdsa.PublicKey
func (k *rsaPublicKey) CryptoPublicKey() crypto.PublicKey {
	return k.PublicKey
}

func (k *rsaPublicKey) toMap() map[string]interface{} {
	jwk := make(map[string]interface{})
	for k, v := range k.extended {
		jwk[k] = v
	}
	jwk["kty"] = k.KeyType()
	jwk["kid"] = k.KeyID()
	jwk["n"] = joseBase64UrlEncode(k.N.Bytes())
	jwk["e"] = joseBase64UrlEncode(serializeRSAPublicExponentParam(k.E))

	return jwk
}

// MarshalJSON serializes this Public Key using the JWK JSON serialization format for
// RSA keys.
func (k *rsaPublicKey) MarshalJSON() (data []byte, err error) {
	return json.Marshal(k.toMap())
}

func rsaPublicKeyFromMap(jwk map[string]interface{}) (*rsaPublicKey, error) {
	// JWK key type (kty) has already been determined to be "RSA".
	// Need to extract 'n', 'e', and 'kid' and check for
	// consistency.

	// Get the modulus parameter N.
	nB64Url, err := stringFromMap(jwk, "n")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key modulus: %s", err)
	}

	n, err := parseRSAModulusParam(nB64Url)
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key modulus: %s", err)
	}

	// Get the public exponent E.
	eB64Url, err := stringFromMap(jwk, "e")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key exponent: %s", err)
	}

	e, err := parseRSAPublicExponentParam(eB64Url)
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key exponent: %s", err)
	}

	key := &rsaPublicKey{
		PublicKey: &rsa.PublicKey{N: n, E: e},
	}

	// Key ID is optional, but if it exists, it should match the key.
	_, ok := jwk["kid"]
	if ok {
		kid, err := stringFromMap(jwk, "kid")
		if err != nil {
			return nil, fmt.Errorf("JWK RSA Public Key ID: %s", err)
		}
		if kid != key.KeyID() {
			return nil, fmt.Errorf("JWK RSA Public Key ID does not match: %s", kid)
		}
	}

	if _, ok := jwk["d"]; ok {
		return nil, fmt.Errorf("JWK RSA Public Key cannot contain private exponent")
	}

	key.extended = jwk

	return key, nil
}
