package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
	"github.com/fernandolobato/cms"
	"github.com/mastahyeti/cms/protocol"
	"github.com/mastahyeti/cms/oid"
)

var (
	IndirectDataContextOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	PEImageDataOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
)

func main() {

	certFile := flag.String("kek-file", "", "")
	keyID := flag.String("kek", "", "")
	moduleDigestStr := flag.String("digest", "", "")
	out := flag.String("out", "", "")
	
	flag.Parse()
	
	oauthClient, err := google.DefaultClient(context.Background(), cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}

	kms, err := cloudkms.New(oauthClient)
	if err != nil {
		log.Fatal(err)
	}
	
	signer, err := NewGoogleKMSSigner(kms, *keyID)
	if err != nil {
		log.Fatal(err)
	}

	pemBlock, err := ioutil.ReadFile(*certFile)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(pemBlock)
	if block == nil {
		log.Fatal(fmt.Errorf("error decoding certificate."))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	modDigest, err := hex.DecodeString(*moduleDigestStr)
	if err != nil {
		log.Fatal(err)
	}

	outFile, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	// requires CMS fork which will not calculate the data digest, 
	// but rather just use this as digest for the signature.
	signedData, err := cms.NewSignedData(modDigest)
	if err != nil {
		log.Fatal(err)
	}

	err = signedData.Sign([]*x509.Certificate{cert}, signer, modDigest)
	if err != nil {
		log.Fatal(err)
	}

	idc, err := IDC(modDigest)
	if err != nil {
		log.Fatal(err)
	}

	signedData.Data().EncapContentInfo = protocol.EncapsulatedContentInfo{
		EContentType: IndirectDataContextOID,
		EContent: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      idc,
			IsCompound: true,
		},
	}
	signedData.AddTimestamps("http://timestamp.digicert.com")

	derEncoded, _ := signedData.ToDER()
	io.Copy(outFile, bytes.NewReader(derEncoded))
}

/*---------------------------------------
	KMS Wrapper using old API version
----------------------------------------*/

type GoogleKMS struct {
	Client        *cloudkms.Service
	keyResourceId string
	publicKey     crypto.PublicKey
	digest []byte
}

func NewGoogleKMSSigner(client *cloudkms.Service, keyResourceId string) (*GoogleKMS, error) {
	g := &GoogleKMS{
		keyResourceId: keyResourceId,
		Client:        client,
	}

	err := g.getAsymmetricPublicKey()
	if err != nil {
		return nil, err
	}

	return g, nil
}

func (g *GoogleKMS) Public() crypto.PublicKey {
	return g.publicKey
}

func (g *GoogleKMS) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	digest64 := base64.StdEncoding.EncodeToString(digest)

	req := &cloudkms.AsymmetricSignRequest{
		Digest: &cloudkms.Digest{
			Sha256: digest64,
		},
	}
	response, err := g.Client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricSign(g.keyResourceId, req).Context(context.Background()).Do()
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.Signature)
}

func (g *GoogleKMS) getAsymmetricPublicKey() error {
	response, err := g.Client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		GetPublicKey(g.keyResourceId).Context(context.Background()).Do()
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("not a public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	g.publicKey = publicKey
	return nil
}

/*---------------------------------------
		Indirect Data Context
----------------------------------------*/
func IDC(moduleDigest []byte) ([]byte, error){
	
	obsolete := []byte {
		0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62,
		0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74,
		0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e,
	}

	idc_peid := IDC_PEID{
		File: IDC_LINK{
			Ftype: 2,
			Value: IDC_STRING{
				Ftype: 0,
				Value: asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag: 30,
					Bytes: obsolete, 
				},
			},
		},
	}

	idc_peid_octets, err := asn1.Marshal(idc_peid)
	if err != nil {
		log.Fatal(err)
	}
	
	idc := IndirectDataContext{
		Data: IndirectDataContextTypeValue{
			ObjType: PEImageDataOID,
			Value: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				Bytes:      idc_peid_octets,
				IsCompound: true,
			},
		},
		Digest: IndirectDataContextDigest{
			Algorithm: X509_ALGOR{
				Algorithm: oid.DigestAlgorithmSHA256,
				Parameter: asn1.RawValue{Tag: asn1.TagNull},
			},
			Digest: moduleDigest,
		},
	}

	octets, err := asn1.Marshal(idc)
	if err != nil {
		return nil, err
	}

	return octets, nil
}

/*---------------------------------------------------------------------------------------------------------------------
		Indirect Data Definition Context
		https://github.com/msekletar/sbsigntool/blob/a6043253a4f8621b8eac0fd099e26a8a992cb13a/src/idc.c#L115
----------------------------------------------------------------------------------------------------------------------*/
type IndirectDataContext struct {
	Data IndirectDataContextTypeValue
	Digest IndirectDataContextDigest
}

type IndirectDataContextTypeValue struct {
	ObjType	asn1.ObjectIdentifier
	Value 	asn1.RawValue
}

type IndirectDataContextDigest struct {
	Algorithm X509_ALGOR
	Digest asn1.RawContent
}

type X509_ALGOR struct {
	Algorithm asn1.ObjectIdentifier
	Parameter asn1.RawValue
}

type IDC_PEID struct {
	Flags asn1.BitString
	File  IDC_LINK
}

type IDC_LINK struct {
	Ftype int
	Value IDC_STRING
}

type IDC_STRING struct {
	Ftype int
	Value asn1.RawValue
}
