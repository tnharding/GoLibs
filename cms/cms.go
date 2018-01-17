//cms package describes the Cryptographic Message Syntax (CMS).  This
//syntax is used to digitally sign, digest, authenticate, or encrypt
//arbitrary message content.
package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
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
	Raw         asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,explicit,default:0,tag:0"`
}

type signedData struct {
	Raw              asn1.RawContent
	Version          int `asn1:"explicit"`
	DigestAlgorithms []digestAlgorithmIdentifier
	EncapContentInfo []encapsulatedContentInfo
	Certficates      []certificate `asn1:"optional,tag:0"`
	Crls             []crl         `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo
}

type digestAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawContent
}

type encapsulatedContentInfo struct {
	EcontentType asn1.ObjectIdentifier
	Econtent     []byte `asn1:"optional,explicit,tag:0"` //[0] EXPLICIT OCTET STRING OPTIONAL
}

type certificate struct {
	Raw asn1.RawContent
}

type crl struct {
	Raw asn1.RawContent
}

type signerInfo struct {
	Version            int `asn1:"explicit"`
	Sid                signerIdentifier
	DigestAlgorithm    digestAlgorithmIdentifier
	SignedAttrs        SignedAttributes `asn1:"optional, implicit, tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          signatureValue
	UnsignedAttrs      []attributes `asn1:"implicit,optional,tag:1"`
}

type signerIdentifier struct {
	IssuerAndSerialNumber issuerAndSerialNumber
	SubjectKeyIdentifier  subjectKeyIdentifier `asn1:"optional, tag:0"`
}
