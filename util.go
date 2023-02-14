package libtrust

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// joseBase64UrlEncode encodes the given data using the standard base64 url
// encoding format but with all trailing '=' characters omitted in accordance
// with the jose specification.
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-2
func joseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// joseBase64UrlDecode decodes the given string using the standard base64 url
// decoder but first adds the appropriate number of trailing '=' characters in
// accordance with the jose specification.
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-2
func joseBase64UrlDecode(s string) ([]byte, error) {
	s = strings.Replace(s, "\n", "", -1)
	s = strings.Replace(s, " ", "", -1)
	switch len(s) % 4 {
	case 0:
	case 2:
		s += "=="
	case 3:
		s += "="
	default:
		return nil, errors.New("illegal base64url string")
	}
	return base64.URLEncoding.DecodeString(s)
}

func keyIDEncode(b []byte) string {
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
	var buf bytes.Buffer
	var i int
	for i = 0; i < len(s)/4-1; i++ {
		start := i * 4
		end := start + 4
		buf.WriteString(s[start:end] + ":")
	}
	buf.WriteString(s[i*4:])
	return buf.String()
}

func keyIDFromCryptoKey(pubKey PublicKey) string {
	// Generate and return a 'libtrust' fingerprint of the public key.
	// For an RSA key this should be:
	//   SHA256(DER encoded ASN1)
	// Then truncated to 240 bits and encoded into 12 base32 groups like so:
	//   ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey.CryptoPublicKey())
	if err != nil {
		return ""
	}
	hasher := crypto.SHA256.New()
	hasher.Write(derBytes)
	return keyIDEncode(hasher.Sum(nil)[:30])
}

func stringFromMap(m map[string]interface{}, key string) (string, error) {
	val, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%q value not specified", key)
	}

	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%q value must be a string", key)
	}
	delete(m, key)

	return str, nil
}

func parseECCoordinate(cB64Url string, curve elliptic.Curve) (*big.Int, error) {
	curveByteLen := (curve.Params().BitSize + 7) >> 3

	cBytes, err := joseBase64UrlDecode(cB64Url)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}
	cByteLength := len(cBytes)
	if cByteLength != curveByteLen {
		return nil, fmt.Errorf("invalid number of octets: got %d, should be %d", cByteLength, curveByteLen)
	}
	return new(big.Int).SetBytes(cBytes), nil
}

func parseRSAModulusParam(nB64Url string) (*big.Int, error) {
	nBytes, err := joseBase64UrlDecode(nB64Url)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}

	return new(big.Int).SetBytes(nBytes), nil
}

func serializeRSAPublicExponentParam(e int) []byte {
	// We MUST use the minimum number of octets to represent E.
	// E is supposed to be 65537 for performance and security reasons
	// and is what golang's rsa package generates, but it might be
	// different if imported from some other generator.
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(e))
	var i int
	for i = 0; i < 8; i++ {
		if buf[i] != 0 {
			break
		}
	}
	return buf[i:]
}

func parseRSAPublicExponentParam(eB64Url string) (int, error) {
	eBytes, err := joseBase64UrlDecode(eB64Url)
	if err != nil {
		return 0, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}
	// Only the minimum number of bytes were used to represent E, but
	// binary.BigEndian.Uint32 expects at least 4 bytes, so we need
	// to add zero padding if necassary.
	byteLen := len(eBytes)
	buf := make([]byte, 4-byteLen, 4)
	eBytes = append(buf, eBytes...)

	return int(binary.BigEndian.Uint32(eBytes)), nil
}
