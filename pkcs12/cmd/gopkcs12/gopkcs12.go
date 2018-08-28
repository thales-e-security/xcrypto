package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/thales-e-security/xcrypto/pkcs12"
	"io/ioutil"
	"os"
)

var password string
var iterations int
var saltLength int
var outputPath string

func main() {
	flag.StringVar(&password, "password", "", "PFX password")
	flag.IntVar(&iterations, "iterations", 32768, "PKBDF2 iteration count")
	flag.IntVar(&saltLength, "salt", 20, "PKBDF2 salt length")
	flag.StringVar(&outputPath, "output", "default.pfx", "PFX filename")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `%s [OPTIONS] ACTION...

Actions:
  keyid HEX        hexadecimal value of key ID attribute
  cert PATH        certificate to include
  key PATH         key to include
  closesafe        close safecontents without encryption
  encryptsafe      close safecontents with encryption
  closepfx         close PFX

Options:
`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := process(flag.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err.Error())
		os.Exit(1)
	}
}

func process(args []string) (err error) {
	enc := pkcs12.NewEncoder()
	enc.Iterations = iterations
	enc.SaltLength = saltLength
	i := 0
	for i < len(args) {
		switch args[i] {
		case "keyid":
			var keyid []byte
			if keyid, err = hex.DecodeString(args[i+1]); err != nil {
				return
			}
			if err = enc.AddBinaryAttribute(pkcs12.OidLocalKeyID, keyid); err != nil {
				return
			}
			i += 2
		case "name":
			if err = enc.AddStringAttribute(pkcs12.OidFriendlyName, args[i+1]); err != nil {
				return
			}
			i += 2
		case "cert":
			var p *pem.Block
			if p, err = getPem(args[i+1]); err != nil {
				return
			}
			if err = enc.AddCertificate(p.Bytes); err != nil {
				return
			}
			i += 2
		case "key":
			var p *pem.Block
			if p, err = getPem(args[i+1]); err != nil {
				return
			}
			var k interface{}
			if k, err = x509.ParsePKCS1PrivateKey(p.Bytes); err != nil {
				return
			}
			if err = enc.AddKey(password, true, k); err != nil {
				return
			}
			i += 2
		case "closesafe":
			if err = enc.CloseSafe("", false); err != nil {
				return
			}
			i += 1
		case "encryptsafe":
			if err = enc.CloseSafe(password, true); err != nil {
				return
			}
			i += 1
		case "closepfx":
			var pfx []byte
			if pfx, err = enc.ClosePfx(password, true); err != nil {
				return
			}
			if err = ioutil.WriteFile(outputPath, pfx, 0666); err != nil {
				return
			}
			i += 1
		default:
			err = errors.New("unrecognized argument: " + args[i])
			return
		}
	}
	return
}

func getPem(path string) (p *pem.Block, err error) {
	var b, rest []byte
	if b, err = ioutil.ReadFile(path); err != nil {
		return
	}
	if p, rest = pem.Decode(b); len(rest) > 0 {
		err = errors.New("cannot decode PEM: " + path)
		return
	}
	return
}
