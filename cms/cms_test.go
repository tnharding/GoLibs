package cms

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestParseCMSContentType(t *testing.T) {

	file, err := os.Open("signedData.asn1")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal("Error opening file")
	}

	oid, err := ParseCMSContentType(data)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(oid)
}
