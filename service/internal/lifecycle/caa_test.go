// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"encoding/binary"
	"testing"
)

func TestParseCAAResponseReadsCAARecordAndDNSSECADBit(t *testing.T) {
	query, id, err := buildCAAQuery("edge.example.test")
	if err != nil {
		t.Fatalf("buildCAAQuery returned error: %v", err)
	}
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8120)
	binary.BigEndian.PutUint16(response[6:8], 1)
	rdata := append([]byte{0, 5}, []byte("issue")...)
	rdata = append(rdata, []byte("ca.example")...)
	response = append(response,
		0xc0, 0x0c,
		byte(dnsTypeCAA>>8), byte(dnsTypeCAA&0xff),
		0, 1,
		0, 0, 0, 60,
		byte(len(rdata)>>8), byte(len(rdata)),
	)
	response = append(response, rdata...)

	result, found, err := parseCAAResponse(response, id)
	if err != nil {
		t.Fatalf("parseCAAResponse returned error: %v", err)
	}
	if !found || result.DNSSECStatus != CAADNSSECSecure || len(result.Records) != 1 {
		t.Fatalf("result = %#v, found = %t", result, found)
	}
	if result.Records[0].Tag != "issue" || result.Records[0].Value != "ca.example" {
		t.Fatalf("record = %#v", result.Records[0])
	}
}
