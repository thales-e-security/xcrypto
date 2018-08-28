// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkcs12 implements some of PKCS#12.
//
// This implementation is distilled from https://tools.ietf.org/html/rfc7292
// and referenced documents. It is intended for decoding P12/PFX-stored
// certificates and keys for use with the crypto/tls package.
package pkcs12

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

var (
	oidDataContentType          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidEncryptedDataContentType = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})

	// OidFriendlyName is the PKCS#9 friendlyName attribute identifier
	OidFriendlyName = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 20})
	// OidLocalKeyID is the PKCS#9 localKeyID attribute identifier
	OidLocalKeyID       = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 21})
	oidMicrosoftCSPName = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 17, 1})
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.AlgorithmIdentifier
}

func (i encryptedPrivateKeyInfo) Data() []byte {
	return i.EncryptedData
}

// PEM block types
const (
	certificateType = "CERTIFICATE"
	privateKeyType  = "PRIVATE KEY"
)

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshaling.
func unmarshal(in []byte, out interface{}) error {
	trailing, err := asn1.Unmarshal(in, out)
	if err != nil {
		return err
	}
	if len(trailing) != 0 {
		return errors.New("pkcs12: trailing data found")
	}
	return nil
}

// ToPEM converts all "safe bags" contained in pfxData to PEM blocks.
func ToPEM(pfxData []byte, password string) ([]*pem.Block, error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, ErrIncorrectPassword
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword)

	if err != nil {
		return nil, err
	}

	blocks := make([]*pem.Block, 0, len(bags))
	for _, bag := range bags {
		block, err := convertBag(&bag, encodedPassword)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}

	return blocks, nil
}

func convertBag(bag *safeBag, password []byte) (*pem.Block, error) {
	block := &pem.Block{
		Headers: make(map[string]string),
	}

	for _, attribute := range bag.Attributes {
		k, v, err := convertAttribute(&attribute)
		if err != nil {
			return nil, err
		}
		block.Headers[k] = v
	}

	switch {
	case bag.Id.Equal(oidCertBag):
		block.Type = certificateType
		certsData, err := decodeCertBag(bag.Value.Bytes)
		if err != nil {
			return nil, err
		}
		block.Bytes = certsData
	case bag.Id.Equal(oidPKCS8ShroudedKeyBag):
		block.Type = privateKeyType

		key, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey:
			block.Bytes = x509.MarshalPKCS1PrivateKey(key)
		case *ecdsa.PrivateKey:
			block.Bytes, err = x509.MarshalECPrivateKey(key)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	default:
		return nil, errors.New("don't know how to convert a safe bag of type " + bag.Id.String())
	}
	return block, nil
}

func convertAttribute(attribute *pkcs12Attribute) (key, value string, err error) {
	isString := false

	switch {
	case attribute.Id.Equal(OidFriendlyName):
		key = "friendlyName"
		isString = true
	case attribute.Id.Equal(OidLocalKeyID):
		key = "localKeyId"
	case attribute.Id.Equal(oidMicrosoftCSPName):
		// This key is chosen to match OpenSSL.
		key = "Microsoft CSP Name"
		isString = true
	default:
		return "", "", errors.New("pkcs12: unknown attribute with OID " + attribute.Id.String())
	}

	if isString {
		if err := unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
			return "", "", err
		}
		if value, err = decodeBMPString(attribute.Value.Bytes); err != nil {
			return "", "", err
		}
	} else {
		var id []byte
		if err := unmarshal(attribute.Value.Bytes, &id); err != nil {
			return "", "", err
		}
		value = hex.EncodeToString(id)
	}

	return key, value, nil
}

// Decode extracts a certificate and private key from pfxData. This function
// assumes that there is only one certificate and only one private key in the
// pfxData.
func Decode(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, err error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword)
	if err != nil {
		return nil, nil, err
	}

	if len(bags) != 2 {
		err = errors.New("pkcs12: expected exactly two safe bags in the PFX PDU")
		return
	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			if certificate != nil {
				err = errors.New("pkcs12: expected exactly one certificate bag")
			}

			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, nil, err
			}
			if len(certs) != 1 {
				err = errors.New("pkcs12: expected exactly one certificate in the certBag")
				return nil, nil, err
			}
			certificate = certs[0]

		case bag.Id.Equal(oidPKCS8ShroudedKeyBag):
			if privateKey != nil {
				err = errors.New("pkcs12: expected exactly one key bag")
			}

			if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword); err != nil {
				return nil, nil, err
			}
		}
	}

	if certificate == nil {
		return nil, nil, errors.New("pkcs12: certificate missing")
	}
	if privateKey == nil {
		return nil, nil, errors.New("pkcs12: private key missing")
	}

	return
}

func getSafeContents(p12Data, password []byte) (bags []safeBag, updatedPassword []byte, err error) {
	pfx := new(pfxPdu)
	if err := unmarshal(p12Data, pfx); err != nil {
		return nil, nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
	}

	if pfx.Version != 3 {
		return nil, nil, NotImplementedError("can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, err
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		return nil, nil, errors.New("pkcs12: no MAC in data")
	}

	if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		if err == ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
			// some implementations use an empty byte array
			// for the empty string password try one more
			// time with empty-empty password
			password = nil
			err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password)
		}
		if err != nil {
			return nil, nil, err
		}
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, nil, err
	}

	if len(authenticatedSafe) != 2 {
		return nil, nil, NotImplementedError("expected exactly two items in the authenticated safe")
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, nil, err
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return nil, nil, err
			}
			if encryptedData.Version != 0 {
				return nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, password); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}

		var safeContents []safeBag
		if err := unmarshal(data, &safeContents); err != nil {
			return nil, nil, err
		}
		bags = append(bags, safeContents...)
	}

	return bags, password, nil
}

// Encoder is a PKCS#12 encoder.
//
// The caller should:
//
// 1. Fill in the parameters.
// 2. For each safe, call Add*Attribute(), AddKey() and AddCertificate() as desired, then CloseSafe().
// 3. Call ClosePfx().
//
// Note that Decode() requires that the PFX contain exactly one key
// and exactly one certificate, in separate safes.
type Encoder struct {
	// Encryption algorithm.
	EncAlgorithm Algorithm

	// Encryption algorithm.
	MacAlgorithm Algorithm

	// PBKDF2 iteration count.
	Iterations int

	// PBKDF2 salt length (bytes).
	SaltLength int

	// SafeContents ::= SEQUENCE OF SafeBag
	safeContents []safeBag

	// AuthenticatedSafe ::= SEQUENCE OF ContentInfo
	authenticatedSafe []contentInfo

	// bagAttributes SET OF PKCS12Attribute OPTIONAL
	Attributes []pkcs12Attribute
}

// Algorithm defines an encryption/MAC algorithm.
type Algorithm int

const (
	// AlgEncPBKDF2DES3 represents DES3 encryption.
	AlgEncPBKDF2DES3 = Algorithm(1)

	// AlgMacPBKDF2HMACSHA1 represents HMAC-SHA1.
	AlgMacPBKDF2HMACSHA1 = Algorithm(3)
)

// NewEncoder creates a new encoder with default parameters.
func NewEncoder() (enc *Encoder) {
	enc = &Encoder{}
	enc.EncAlgorithm = AlgEncPBKDF2DES3
	enc.MacAlgorithm = AlgMacPBKDF2HMACSHA1
	enc.Iterations = 32768
	enc.SaltLength = 20 // RFC7292 s6
	return
}

// AddBinaryAttribute adds an octet string attribute to the next entry in this safe.
//
// The attribute will apply to the next certificate or key added with
// AddCertificate() or AddKey().
func (enc *Encoder) AddBinaryAttribute(oid asn1.ObjectIdentifier, value []byte) (err error) {
	if err = enc.addAttribute(oid, value); err != nil {
		return
	}
	return
}

// AddStringAttribute adds a BMPString attribute to the next entry in this safe.
//
// The attribute will apply to the next certificate or key added with
// AddCertificate() or AddKey().
func (enc *Encoder) AddStringAttribute(oid asn1.ObjectIdentifier, value string) (err error) {
	// Encode the string as a BMPString...
	var stringValue asn1.RawValue
	stringValue.Class = asn1.ClassUniversal
	stringValue.Tag = 30           // would like to say asn1.TagBMPString
	stringValue.IsCompound = false // primitive form
	if stringValue.Bytes, err = normalBmpString(value); err != nil {
		return
	}
	if err = enc.addAttribute(oid, stringValue); err != nil {
		return
	}
	return
}

// addAttribute adds an arbitrary attribute to the next entry in this safe.
func (enc *Encoder) addAttribute(oid asn1.ObjectIdentifier, value interface{}) (err error) {
	var rawValue asn1.RawValue
	rawValue.Class = asn1.ClassUniversal
	rawValue.Tag = asn1.TagSet
	rawValue.IsCompound = true
	if rawValue.Bytes, err = asn1.Marshal(value); err != nil {
		err = errors.New("pkcs12: encoding attribute value: " + err.Error())
		return
	}
	enc.Attributes = append(enc.Attributes, pkcs12Attribute{oid, rawValue})
	return
}

// AddCertificate adds a certificate to the current SafeContents.
func (enc *Encoder) AddCertificate(x509Certificates []byte) (err error) {
	var asn1data []byte
	if asn1data, err = encodeCertBag(x509Certificates); err != nil {
		return
	}
	var s safeBag
	s.Id = oidCertBag
	s.Value.Class = asn1.ClassContextSpecific
	s.Value.Tag = 0
	s.Value.IsCompound = true
	s.Value.Bytes = asn1data
	s.Attributes = enc.Attributes
	enc.Attributes = nil
	enc.safeContents = append(enc.safeContents, s)
	return
}

// getSalt generates random salt for a key derivation.
func (enc *Encoder) getSalt() (salt []byte, err error) {
	salt = make([]byte, enc.SaltLength)
	if _, err = rand.Read(salt); err != nil {
		err = errors.New("pkcs12: error generating salt: " + err.Error())
		return
	}
	return
}

// getEncAlgorithm return a fully parameterized instance of the configured encryption
// algorithm, ready for passing to pbEncrypt().
func (enc *Encoder) getEncAlgorithm() (algorithm pkix.AlgorithmIdentifier, err error) {
	switch enc.EncAlgorithm {
	case AlgEncPBKDF2DES3:
		algorithm.Algorithm = oidPBEWithSHAAnd3KeyTripleDESCBC
	default:
		err = errors.New("pkcs12: unrecognised EncAlgorithm")
	}
	var params pbeParams
	params.Iterations = enc.Iterations
	if params.Salt, err = enc.getSalt(); err != nil {
		return
	}
	var asn1data []byte
	if asn1data, err = asn1.Marshal(params); err != nil {
		err = errors.New("pkcs12: encoding algorithm parameters: " + err.Error())
		return
	}
	if _, err = asn1.Unmarshal(asn1data, &algorithm.Parameters); err != nil {
		err = errors.New("pkcs12: decoding algorithm parameters: " + err.Error())
		return
	}
	return
}

// AddKey adds a key to the current SafeContents.
//
// The key will be encrypted using the password. (Unencrypted private
// keys are not currently supported.)
func (enc *Encoder) AddKey(password string, encrypt bool, privateKey interface{}) (err error) {
	// Parameter checks
	if !encrypt {
		err = errors.New("pkcs12: must encrypt keys")
		return
	}
	// Convert password
	var encodedPassword []byte
	if encodedPassword, err = bmpString(password); err != nil {
		return
	}
	// Encrypt key
	var asn1data []byte
	var algorithm pkix.AlgorithmIdentifier
	if algorithm, err = enc.getEncAlgorithm(); err != nil {
		return
	}
	if asn1data, err = encodePkcs8ShroudedKeyBag(algorithm, privateKey, encodedPassword); err != nil {
		return
	}
	// Format the ciphertext
	var s safeBag
	s.Id = oidPKCS8ShroudedKeyBag
	s.Value.Class = asn1.ClassContextSpecific
	s.Value.Tag = 0
	s.Value.IsCompound = true
	s.Value.Bytes = asn1data
	s.Attributes = enc.Attributes
	enc.Attributes = nil
	enc.safeContents = append(enc.safeContents, s)
	return
}

// CloseSafe finalizes a SafeContents.
//
// If encrypt==true then the SafeContents will be encrypted using the password.
func (enc *Encoder) CloseSafe(password string, encrypt bool) (err error) {
	// State check
	if len(enc.Attributes) > 0 {
		err = errors.New("pkcs12: CloseSafe with unbound attributes")
		return
	}
	var asn1data []byte
	if asn1data, err = asn1.Marshal(enc.safeContents); err != nil {
		err = errors.New("pkcs12: error encoding cert bag: " + err.Error())
		return
	}
	var c contentInfo
	if encrypt {
		// Encrypt under password
		var encodedPassword []byte
		if encodedPassword, err = bmpString(password); err != nil {
			return
		}
		var algorithm pkix.AlgorithmIdentifier
		if algorithm, err = enc.getEncAlgorithm(); err != nil {
			return
		}
		var encryptedData encryptedData
		encryptedData.Version = 0
		encryptedData.EncryptedContentInfo.ContentType = oidDataContentType
		encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm = algorithm
		if encryptedData.EncryptedContentInfo.EncryptedContent, err = pbEncrypt(algorithm, asn1data, encodedPassword); err != nil {
			return
		}
		if asn1data, err = asn1.Marshal(encryptedData); err != nil {
			err = errors.New("pkcs12: error encoding ciphertext: " + err.Error())
			return
		}
		c.ContentType = oidEncryptedDataContentType
	} else {
		// Don't encrypt
		if asn1data, err = asn1.Marshal(asn1data); err != nil {
			err = errors.New("pkcs12: error encoding content: " + err.Error())
			return
		}
		c.ContentType = oidDataContentType
	}
	c.Content.Class = asn1.ClassContextSpecific
	c.Content.Tag = 0
	c.Content.IsCompound = true
	c.Content.Bytes = asn1data
	enc.authenticatedSafe = append(enc.authenticatedSafe, c)
	// Ready for the next safe
	enc.safeContents = nil
	return
}

// ClosePfx finalizes a PFX and return the resulting byte string.
//
// The PFX will be MACed using the password. Unverified PFXs are not
// supported.
func (enc *Encoder) ClosePfx(password string, mac bool) (p12data []byte, err error) {
	// Parameter/state checks
	if !mac {
		err = errors.New("pkcs12: must MAC")
		return
	}
	if enc.safeContents != nil {
		err = errors.New("pkcs12: ClosePfx without CloseSafe")
		return
	}
	// PFX structure
	var pfx pfxPdu
	pfx.Version = 3
	pfx.AuthSafe.ContentType = oidDataContentType
	// Translate the password
	var encodedPassword []byte
	if encodedPassword, err = bmpString(password); err != nil {
		return
	}
	// Identify the MAC algorithm
	switch enc.MacAlgorithm {
	case AlgMacPBKDF2HMACSHA1:
		pfx.MacData.Mac.Algorithm.Algorithm = oidSHA1
	default:
		err = errors.New("pkcs12: unrecognised MacAlgorithm")
		return
	}
	// Set the MAC parameters
	pfx.MacData.Iterations = enc.Iterations
	if pfx.MacData.MacSalt, err = enc.getSalt(); err != nil {
		return
	}
	// Encode the AuthenticatedSafe
	var asn1data []byte
	if asn1data, err = asn1.Marshal(enc.authenticatedSafe); err != nil {
		err = errors.New("pkcs12: error encoding AuthenticatedSafe: " + err.Error())
		return
	}
	// MAC the contents
	if pfx.MacData.Mac.Digest, err = computeMac(&pfx.MacData, asn1data, encodedPassword); err != nil {
		err = errors.New("pkcs12: error computing MAC: " + err.Error())
		return
	}
	// Encode the AuthenticatedSafe again
	if asn1data, err = asn1.Marshal(asn1data); err != nil {
		err = errors.New("pkcs12: error encoding encoded AuthenticatedSafe: " + err.Error())
		return
	}
	pfx.AuthSafe.Content.Class = asn1.ClassContextSpecific
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	pfx.AuthSafe.Content.Bytes = asn1data
	// Marshal the PFX
	if p12data, err = asn1.Marshal(pfx); err != nil {
		err = errors.New("pkcs12: error encoding PFX: " + err.Error())
		return
	}
	return
}
