package main

import (
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

type Certificate struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type TBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm AlgorithmIdentifier
	Issuer             RDNSequence
	Validity           Validity
	Subject            RDNSequence
	PublicKey          PublicKeyInfo
}

type AlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type RDNSequence []RelativeDistinguishedNameSET

type RelativeDistinguishedNameSET []AttributeTypeAndValue

type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type Validity struct {
	NotBefore, NotAfter time.Time
}

type PublicKeyInfo struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,explicit,default:0,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []digestAlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certficates      []Certificate `asn1:"implicit, optional,tag:0"`
	Crls             []crl         `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type signerInfo struct {
	Version            int
	Sid                signerIdentifier
	DigestAlgorithm    digestAlgorithmIdentifier
	SignedAttrs        signedAttributes `asn1:"optional, implicit, tag:0"`
	SignatureAlgorithm digestAlgorithmIdentifier
	//Signature          signatureValue
	//UnsignedAttrs      []attributes `asn1:"implicit,optional,tag:1"`
}

type signedAttributes struct {
	SignedAttr []AttributeTypeAndValue
}

type signerIdentifier struct {
	Raw asn1.RawContent
	//IssuerAndSerialNumber issuerAndSerialNumber
	//SubjectKeyIdentifier  int `asn1:"optional, tag:0"`
}

type issuerAndSerialNumber struct {
	Issuer       RelativeDistinguishedNameSET
	SerialNumber []byte
}

type crl struct {
	Raw asn1.RawContent
}

type encapsulatedContentInfo struct {
	EcontentType asn1.ObjectIdentifier
}

type digestAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

var ContentInfo contentInfo
var SignedData signedData

func main() {

	file, err := os.Open("signedData.asn1")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal("Error opening file")
	}

	_, err2 := asn1.Unmarshal(b, &ContentInfo)
	if err2 != nil {
		log.Fatal(err2)
	}

	_, err2 = asn1.Unmarshal(ContentInfo.Content.Bytes, &SignedData)
	if err2 != nil {
		log.Fatal(err2)
	}

	fmt.Println(SignedData)
}
