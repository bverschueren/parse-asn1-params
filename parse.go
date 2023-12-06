package main
import (
        "golang.org/x/crypto/cryptobyte"
        "fmt"
        "io"
        "os"
	"crypto/x509/pkix"
	"errors"

	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)
func main() {
        in, _ := io.ReadAll(os.Stdin)

	input := cryptobyte.String(in)
	// we read the SEQUENCE including length and tag bytes so that
	// we can populate Certificate.Raw, before unwrapping the
	// SEQUENCE so it can be operated on

  	var tbs cryptobyte.String
  	// do the same trick again as above to extract the raw
  	// bytes for Certificate.RawTBSCertificate
  	if !input.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) {
  		fmt.Errorf("x509: malformed tbs certificate")
  	}

	var spki cryptobyte.String
	if !tbs.ReadASN1Element(&spki, cryptobyte_asn1.SEQUENCE) {
		fmt.Errorf("x509: malformed spki")
	}

	var pkAISeq cryptobyte.String
	if !spki.ReadASN1(&pkAISeq, cryptobyte_asn1.SEQUENCE) {
		fmt.Errorf("x509: malformed public key algorithm identifier")
	}
	pkAI, err := parseAI(pkAISeq)
	if err != nil {
		fmt.Errorf("err: %s", err)
	}
	fmt.Printf("parameters: %x", pkAI.Parameters)
}

func parseAI(der cryptobyte.String) (pkix.AlgorithmIdentifier, error) {
	ai := pkix.AlgorithmIdentifier{}
	if !der.ReadASN1ObjectIdentifier(&ai.Algorithm) {
		return ai, errors.New("x509: malformed OID")
	}
	if der.Empty() {
		return ai, nil
	}
	var params cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !der.ReadAnyASN1Element(&params, &tag) {
		return ai, errors.New("x509: malformed parameters")
	}
	ai.Parameters.Tag = int(tag)
	ai.Parameters.FullBytes = params
	return ai, nil
}
