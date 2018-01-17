package main

import (
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

var ContentInfo contentInfo
var SignedData signedData

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
	Raw asn1.RawValue
	//IssuerAndSerialNumber issuerAndSerialNumber
	//SubjectKeyIdentifier  int `asn1:"optional, tag:0"`
}

type issuerAndSerialNumber struct {
	Raw         asn1.RawValue
	RDNsequence []rdn `asn1:"set"`
	//SerialNumber []byte
}

var IssuerAndSerialNumber issuerAndSerialNumber

type rdn struct {
	Raw   asn1.RawValue
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type RelativeDistinguishedNameSET []AttributeTypeAndValue

type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type myCertificate struct {
	Raw asn1.RawContent
}

type digestAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue //`asn1:"optional,explicit,default:0,tag:0"`
}

type encapsulatedContentInfo struct {
	EcontentType asn1.ObjectIdentifier
}

type signedData struct {
	Version          int
	DigestAlgorithms []digestAlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certficates      []myCertificate `asn1:"implicit, optional,tag:0"`
	//	Crls             []crl         `asn1:"optional,tag:1"`
	SignerInfos []signerInfo `asn1:"set"`
}

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

	_, err = asn1.Unmarshal(b, &ContentInfo)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ContentInfo.ContentType)
	//fmt.Println(ContentInfo.Content)

	//unparse signed data
	_, err = asn1.Unmarshal(ContentInfo.Content.Bytes, &SignedData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(SignedData.Version)
	fmt.Println(SignedData.DigestAlgorithms)
	fmt.Println(SignedData.EncapContentInfo.EcontentType)
	//for _, cert := range SignedData.Certficates {
	//	fmt.Println(cert.Raw)
	//}

	for _, signer := range SignedData.SignerInfos {
		fmt.Println(signer.DigestAlgorithm)
	}
}
