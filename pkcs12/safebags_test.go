package pkcs12

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"
)

var safebagTestPassword = []byte("bWFkZSB5b3UgbG9vawo=")

func generateRsa(t *testing.T) (k interface{}, err error) {
	if k, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		t.Errorf("rsa.GenerateKey: %s", err)
		return
	}
	return
}

func generateEcdsa(t *testing.T) (k interface{}, err error) {
	if k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Errorf("ecdsa.GenerateKey: %s", err)
		return
	}
	return
}

type keyType struct {
	Name     string
	Generate func(*testing.T) (interface{}, error)
}

// We support the key types supported by crypto/x509/pkcs8
var keyTypes = []keyType{
	{
		"RSA",
		generateRsa,
	},
	{
		"ECDSA",
		generateEcdsa,
	},
}

func TestEncodeKeyBag(t *testing.T) {
	var err error
	var algorithm = pkix.AlgorithmIdentifier{
		Algorithm: sha1WithTripleDES,
	}
	if algorithm.Parameters.FullBytes, err = asn1.Marshal(pbeParams{
		Salt:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	}); err != nil {
		t.Errorf("sn1.Marshal: %s", err)
		return
	}

	for _, kt := range keyTypes {
		// Generate a key
		var generatedKey interface{}
		if generatedKey, err = kt.Generate(t); err != nil {
			continue
		}

		// Encode it
		var asn1Data []byte
		if asn1Data, err = encodePkcs8ShroudedKeyBag(algorithm, generatedKey, safebagTestPassword); err != nil {
			t.Errorf("%s encodePkcs8ShroudedKeyBag: %s", kt.Name, err)
			return
		}

		// Decode with bad password should fail
		if _, err = decodePkcs8ShroudedKeyBag(asn1Data, []byte("junk")); err == nil {
			t.Errorf("%s decodePkcs8ShroudedKeyBag: failed to error with bad password", kt.Name)
		}

		// Decode of truncated input should fail
		if _, err = decodePkcs8ShroudedKeyBag(asn1Data[0:len(asn1Data)-1], safebagTestPassword); err == nil {
			t.Errorf("%s decodePkcs8ShroudedKeyBag: failed to error with truncated data", kt.Name)
			return
		}

		// Decode should succeed...
		var decodedKey interface{}
		if decodedKey, err = decodePkcs8ShroudedKeyBag(asn1Data, safebagTestPassword); err != nil {
			t.Errorf("%s decodePkcs8ShroudedKeyBag: %s", kt.Name, err)
			return
		}

		// ...and produce the original input
		if !reflect.DeepEqual(generatedKey, decodedKey) {
			t.Errorf("%s decodePkcs8ShroudedKeyBag mismatch", kt.Name)
		}

	}
}

func TestEncodeCertificateBag(t *testing.T) {
	cert := []byte("Actually any old rubbish will do here")
	var asn1Data []byte
	var err error

	if asn1Data, err = encodeCertBag(cert); err != nil {
		t.Errorf("encodeCertBag: %s", err)
		return
	}

	var decodedCert []byte
	if decodedCert, err = decodeCertBag(asn1Data); err != nil {
		t.Errorf("decodeCertBag: %s", err)
		return
	}

	if bytes.Compare(cert, decodedCert) != 0 {
		t.Errorf("decodeCertBag: certs don't match")
	}

	if decodedCert, err = decodeCertBag(asn1Data[0 : len(asn1Data)-1]); err == nil {
		t.Errorf("decodeCertBag: failed to error on truncated input")
		return
	}
}
