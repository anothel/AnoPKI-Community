// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

const dnsTypeCAA uint16 = 257

type dnsCAALookup struct {
	resolver string
	timeout  time.Duration
}

func NewDNSCAALookup(resolver string, timeout time.Duration) (CAALookup, error) {
	resolver = strings.TrimSpace(resolver)
	if resolver == "" || timeout <= 0 {
		return nil, domain.ErrInvalidRequest
	}
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}
	return dnsCAALookup{resolver: resolver, timeout: timeout}, nil
}

func (l dnsCAALookup) LookupCAA(ctx context.Context, dnsName string) (CAALookupResult, error) {
	name := strings.TrimSuffix(strings.TrimSpace(dnsName), ".")
	for name != "" {
		result, found, err := l.lookupCAAName(ctx, name)
		if err != nil {
			return CAALookupResult{}, err
		}
		if found {
			return result, nil
		}
		_, rest, ok := strings.Cut(name, ".")
		if !ok {
			return result, nil
		}
		name = rest
	}
	return CAALookupResult{DNSSECStatus: CAADNSSECIndeterminate}, nil
}

func (l dnsCAALookup) lookupCAAName(ctx context.Context, name string) (CAALookupResult, bool, error) {
	query, id, err := buildCAAQuery(name)
	if err != nil {
		return CAALookupResult{}, false, err
	}
	dialer := net.Dialer{Timeout: l.timeout}
	conn, err := dialer.DialContext(ctx, "udp", l.resolver)
	if err != nil {
		return CAALookupResult{}, false, err
	}
	defer conn.Close()
	deadline := time.Now().Add(l.timeout)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(query); err != nil {
		return CAALookupResult{}, false, err
	}
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return CAALookupResult{}, false, err
	}
	return parseCAAResponse(buffer[:n], id)
}

func buildCAAQuery(name string) ([]byte, uint16, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	out := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x0100)
	binary.BigEndian.PutUint16(out[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		labelLen := len(label)
		if labelLen == 0 || labelLen > 63 {
			return nil, 0, domain.ErrInvalidRequest
		}
		out = append(out, byte(labelLen))
		out = append(out, label...)
	}
	out = append(out, 0, byte(dnsTypeCAA>>8), byte(dnsTypeCAA&0xff), 0, 1)
	return out, id, nil
}

func parseCAAResponse(message []byte, id uint16) (CAALookupResult, bool, error) {
	if len(message) < 12 || binary.BigEndian.Uint16(message[0:2]) != id {
		return CAALookupResult{}, false, domain.ErrInvalidRequest
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	status := CAADNSSECIndeterminate
	if flags&0x0020 != 0 {
		status = CAADNSSECSecure
	}
	rcode := flags & 0x000f
	if rcode == 2 {
		return CAALookupResult{DNSSECStatus: CAADNSSECBogus}, true, nil
	}
	if rcode == 3 {
		return CAALookupResult{DNSSECStatus: status}, false, nil
	}
	if rcode != 0 {
		return CAALookupResult{}, false, fmt.Errorf("dns response rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(message[4:6]))
	an := int(binary.BigEndian.Uint16(message[6:8]))
	offset := 12
	var err error
	for i := 0; i < qd; i++ {
		offset, err = skipDNSName(message, offset)
		if err != nil {
			return CAALookupResult{}, false, err
		}
		offset += 4
		if offset > len(message) {
			return CAALookupResult{}, false, domain.ErrInvalidRequest
		}
	}
	records := make([]CAARecord, 0)
	for i := 0; i < an; i++ {
		offset, err = skipDNSName(message, offset)
		if err != nil {
			return CAALookupResult{}, false, err
		}
		if offset+10 > len(message) {
			return CAALookupResult{}, false, domain.ErrInvalidRequest
		}
		rrType := binary.BigEndian.Uint16(message[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(message[offset+2 : offset+4])
		rdLen := int(binary.BigEndian.Uint16(message[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(message) {
			return CAALookupResult{}, false, domain.ErrInvalidRequest
		}
		if rrType == dnsTypeCAA && rrClass == 1 && rdLen >= 2 {
			data := message[offset : offset+rdLen]
			tagLen := int(data[1])
			if 2+tagLen <= len(data) {
				records = append(records, CAARecord{
					Flag:  data[0],
					Tag:   string(data[2 : 2+tagLen]),
					Value: string(data[2+tagLen:]),
				})
			}
		}
		offset += rdLen
	}
	return CAALookupResult{Records: records, DNSSECStatus: status}, len(records) > 0, nil
}

func skipDNSName(message []byte, offset int) (int, error) {
	for {
		if offset >= len(message) {
			return 0, domain.ErrInvalidRequest
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			return offset, nil
		}
		if length&0xc0 == 0xc0 {
			if offset >= len(message) {
				return 0, domain.ErrInvalidRequest
			}
			return offset + 1, nil
		}
		offset += length
		if offset > len(message) {
			return 0, domain.ErrInvalidRequest
		}
	}
}
