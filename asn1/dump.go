package main

import (
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

var ContentInfo contentInfo
var SignedData signedData

type Certificate struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}

type TBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	Issuer             RDNSequence
	Validity           Validity
	Subject            RDNSequence
	PublicKey          PublicKeyInfo
}

type RDNSequence []RelativeDistinguishedNameSET
type RelativeDistinguishedNameSET []AttributeTypeAndValue

type Validity struct {
	NotBefore, NotAfter time.Time
}

type PublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapsulatedInfo encapsulatedContentInfo
	Certificates     []Certificate `asn1:"optional,implicit,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type signerInfo struct {
	Version      int
	Sid          signerIdentifier
	DigestAlg    algorithmIdentifier
	SignedAttrs  []signedAttribute `asn1:"optional,default:0,tag:0"`
	SignatureAlg algorithmIdentifier
	Signature    []byte
}

type signerIdentifier struct {
	Raw    asn1.RawContent
	Rdn    RelativeDistinguishedName
	Serial *big.Int
}

type RelativeDistinguishedName struct {
	Raw asn1.RawContent
}

type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type signedAttribute struct {
	Type  asn1.ObjectIdentifier
	Value value `asn1:"set"`
}

type value struct {
	Raw asn1.RawValue
}

type encapsulatedContentInfo struct {
	Raw asn1.RawContent
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
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

	// //unparse signed data
	// _, err = asn1.Unmarshal(ContentInfo.Content.Bytes, &SignedData)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("SignedData.Version:", SignedData.Version)

	// for _, signer := range SignedData.SignerInfos {
	// 	fmt.Println("SignerInfo.Version:", signer.Version)
	// 	fmt.Println("SignerInfo.Sid:", signer.Sid.Raw)
	// 	fmt.Printf("SignerInfo.Sid.Serial: %x\n", signer.Sid.Serial)

	// 	fmt.Println("SignerInfo.SignedAttrs:")
	// 	for i, sattr := range signer.SignedAttrs {
	// 		fmt.Printf("Attribute %d: oid: %v valueTag: %v\n", i, sattr.Type, sattr.Value.Raw.Tag)
	// 	}
	// 	fmt.Println("SignerInfo.DigestAlg:", signer.DigestAlg)
	// 	fmt.Println("SignerInfo.SignatureAlg:", signer.SignatureAlg)
	// 	fmt.Println("SignerInfo.Signature:", signer.Signature)
	// }
}
