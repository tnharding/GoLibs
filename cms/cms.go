//cms package describes the Cryptographic Message Syntax (CMS).  This
//syntax is used to digitally sign, digest, authenticate, or encrypt
//arbitrary message content.
package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// The following object identifiers identify the content information
//
//       id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//          us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }
//
// The following object identifier identifies the data content type:
//
//       id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// 		 us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
//
// The following object identifier identifies the signed-data content type:
//
//       id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//          us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
//
// The following object identifier identifies the enveloped-data content type:
//
//    id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// 	   us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 }
//
// The following object identifier identifies the digested-data content type:
//
//       id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// 		  us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5 }
//
// The following object identifier identifies the encrypted-data content type:

//       id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// 		  us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6 }
//
// The following object identifier identifies the authenticated-data content type:
//
//       id-ct-authData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//          us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 2 }
//
//
// The following object identifiers identify the attributes
//
// The following object identifier identifies the content-type attribute:
//
//       id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// 		  us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }
//
// The following object identifier identifies the message-digest attribute:
//
//       id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// 		  us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }
//
// The following object identifier identifies the signing-time attribute:
//
//       id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// 		  us(840) rsadsi(113549) pkcs(1) pkcs9(9) 5 }
//
// The following object identifier identifies the countersignature attribute:
//
//       id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// 		  us(840) rsadsi(113549) pkcs(1) pkcs9(9) 6 }
//

var (
	oidContentInfo              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 6}
	oidDataContent              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedDataContent        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedDataContent     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidDigestedDataContent      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidEncryptedDataContent     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidAuthenticatedDataContent = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 2}

	oidContentAttribute          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigestAttribute    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTimeAttribute      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidCounterSignatureAttribute = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	//Content     asn1.RawValue `asn1:"optional,explicit,default:0,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certficates      []Certificate `asn1:"optional,implicit,tag:0"`
	Crls             []crl         `asn1:"optional,implicit,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

// type algorithmIdentifier struct {
// 	Algorithm  asn1.ObjectIdentifier
// 	Parameters asn1.RawValue `asn1:"optional"`
// }

type encapsulatedContentInfo struct {
	Raw asn1.RawContent
}

type crl struct {
	List pkix.TBSCertificateList
}

type signerInfo struct {
	Version      int
	Sid          signerIdentifier
	DigestAlg    pkix.AlgorithmIdentifier
	SignedAttrs  []signedAttribute `asn1:"optional,default:0,tag:0"`
	SignatureAlg pkix.AlgorithmIdentifier
	Signature    []byte
}

type signerIdentifier struct {
	Rdn    RelativeDistinguishedName
	Serial *big.Int
}

type RelativeDistinguishedName struct {
	Raw asn1.RawContent
}

type signedAttribute struct {
	Type  asn1.ObjectIdentifier
	Value value `asn1:"set"`
}

type value struct {
	Raw asn1.RawValue
}

type Certificate struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type TBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             RDNSequence
	Validity           Validity
	Subject            RDNSequence
	PublicKey          PublicKeyInfo
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
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// Unmarshal parses the DER-encoded ASN.1 data structure b
// and uses the reflect package to fill in an arbitrary value pointed at by val.
// Because Unmarshal uses the reflect package, the structs
// being written to must use upper case field names.
//
// ParseCMSContentInfo returns a parse error.
func ParseCMSContentType(b []byte) (asn1.ObjectIdentifier, error) {
	var ContentInfo contentInfo

	_, err := asn1.Unmarshal(b, &ContentInfo)
	if err != nil {
		return nil, err
	}
	return ContentInfo.ContentType, nil
}
