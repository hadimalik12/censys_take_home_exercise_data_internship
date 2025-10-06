package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

/*
HandshakeInfo holds the fields we extract from the MySQL handshake packet.
*/
type HandshakeInfo struct {
	ProtocolVersion  uint8
	ServerVersion    string
	ConnectionID     uint32
	CapabilityFlags  uint32
	CharacterSet     uint8
	StatusFlags      uint16
	AuthPluginName   string
	RawFirstBytesHex string
	Notes            []string
}

/*
readWithDeadline reads into the provided buffer from conn, applying a read deadline.
Function-level comment: sets a read deadline and performs a single Read call; returns bytes read or an error.
*/
func readWithDeadline(conn net.Conn, buf []byte, timeout time.Duration) (int, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	return conn.Read(buf)
}

/*
parseNullTerminated extracts a NUL-terminated string from byte slice starting at start.
Function-level comment: finds the next 0x00, returns the string and the position after the terminator or an error if none found.
*/
func parseNullTerminated(b []byte, start int) (val string, next int, err error) {
	i := start
	for i < len(b) && b[i] != 0x00 {
		i++
	}
	if i >= len(b) {
		return "", 0, errors.New("unterminated string")
	}
	return string(b[start:i]), i + 1, nil
}

/*
parseHandshake interprets the first MySQL packet payload and fills HandshakeInfo.
Function-level comment: given a full packet (header+payload), parse fields per MySQL protocol v10 where possible;
it is defensive about truncated payloads and returns partial info or an error when parsing cannot proceed.
*/
func parseHandshake(b []byte) (*HandshakeInfo, error) {
	if len(b) < 4 {
		return nil, errors.New("short read (no packet header)")
	}
	payloadLen := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	seq := b[3]
	_ = seq

	if len(b) < 4+payloadLen {
		return nil, errors.New("short read (payload incomplete)")
	}
	p := b[4 : 4+payloadLen]

	info := &HandshakeInfo{
		RawFirstBytesHex: hex.EncodeToString(b[:min(len(b), 64)]),
	}

	if len(p) < 1 {
		return nil, errors.New("payload too small for protocol version")
	}
	info.ProtocolVersion = p[0]
	i := 1

	sv, next, err := parseNullTerminated(p, i)
	if err != nil {
		return nil, fmt.Errorf("server version parse error: %w", err)
	}
	info.ServerVersion = sv
	i = next

	if i+4 > len(p) {
		return nil, errors.New("payload too small for connection id")
	}
	info.ConnectionID = binary.LittleEndian.Uint32(p[i : i+4])
	i += 4

	if i+8+1 > len(p) {
		return nil, errors.New("payload too small for auth data part 1")
	}
	i += 8
	i += 1

	if i+2 > len(p) {
		return nil, errors.New("payload too small for capability flags (lower)")
	}
	capLower := binary.LittleEndian.Uint16(p[i : i+2])
	i += 2

	if i >= len(p) {
		info.CapabilityFlags = uint32(capLower)
		return info, nil
	}

	if i+1+2+2 > len(p) {
		info.CapabilityFlags = uint32(capLower)
		return info, nil
	}
	info.CharacterSet = p[i]
	i += 1

	info.StatusFlags = binary.LittleEndian.Uint16(p[i : i+2])
	i += 2

	capUpper := binary.LittleEndian.Uint16(p[i : i+2])
	i += 2

	info.CapabilityFlags = uint32(capLower) | (uint32(capUpper) << 16)

	var authDataLen uint8
	if (info.CapabilityFlags & (1 << 19)) != 0 {
		if i >= len(p) {
			return info, nil
		}
		authDataLen = p[i]
		i += 1
	} else {
		if i < len(p) {
			authDataLen = p[i]
			i += 1
		}
	}

	if i+10 <= len(p) {
		i += 10
	}

	if authDataLen > 0 && i < len(p) {
		need := int(authDataLen) - 8
		if need < 0 {
			need = 0
		}
		if need > 0 {
			if i+need <= len(p) {
				i += need
			} else {
				i = len(p)
			}
		}
	}

	if i < len(p) {
		if name, _, err := parseNullTerminated(p, i); err == nil {
			info.AuthPluginName = name
		}
	}

	return info, nil
}

/*
grabFirstPacket reads the initial MySQL packet (header + payload) from conn.
Function-level comment: reads the 4-byte MySQL packet header to determine payload length and then reads the payload; returns raw header+payload or partial data on timeout/error.
*/
func grabFirstPacket(conn net.Conn, overallTimeout time.Duration) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := readWithDeadline(conn, header, overallTimeout); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	payloadLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if payloadLen <= 0 || payloadLen > 100000 {
		return append(header, []byte{}...), nil
	}
	payload := make([]byte, payloadLen)
	read := 0
	for read < payloadLen {
		n, err := readWithDeadline(conn, payload[read:], overallTimeout)
		if n > 0 {
			read += n
		}
		if err != nil {
			return append(header, payload[:read]...), nil
		}
	}
	return append(header, payload...), nil
}

/*
min is a small helper utility.
Function-level comment: returns the smaller of two integers.
*/
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

/*
escape performs a minimal JSON-safe escaping for a string.
Function-level comment: escapes backslashes, quotes, and common control characters for safe inline JSON printing.
*/
func escape(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"':
			out = append(out, '\\', s[i])
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}

/*
main is the program entrypoint.
Function-level comment: parse flags, dial the target TCP address, read the first packet, parse the handshake, and print JSON-style results indicating whether MySQL was detected and details when available.
*/
func main() {
	host := flag.String("host", "127.0.0.1", "Target host/IP")
	port := flag.Int("port", 3306, "Target TCP port")
	timeout := flag.Duration("timeout", 3*time.Second, "Dial/read timeout")
	verbose := flag.Bool("v", false, "Verbose output (dump hex preview)")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	dialer := net.Dialer{Timeout: *timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("{\"ok\":false,\"mysql\":false,\"error\":\"dial failed: %s\"}\n", escape(err.Error()))
		os.Exit(0)
	}
	defer conn.Close()

	first, err := grabFirstPacket(conn, *timeout)
	if err != nil || len(first) < 4 {
		if err != nil {
			fmt.Printf("{\"ok\":false,\"mysql\":false,\"error\":\"read failed: %s\"}\n", escape(err.Error()))
		} else {
			fmt.Printf("{\"ok\":false,\"mysql\":false,\"error\":\"no data from server\"}\n")
		}
		return
	}

	info, perr := parseHandshake(first)
	if perr != nil {
		if *verbose {
			fmt.Printf("{\"ok\":true,\"mysql\":false,\"reason\":\"%s\",\"first_bytes_hex\":\"%s\"}\n", escape(perr.Error()), hex.EncodeToString(first[:min(len(first), 64)]))
		} else {
			fmt.Printf("{\"ok\":true,\"mysql\":false}\n")
		}
		return
	}

	if !*verbose {
		fmt.Printf("{\"ok\":true,\"mysql\":true,\"server_version\":\"%s\",\"protocol\":%d,\"connection_id\":%d}\n",
			escape(info.ServerVersion), info.ProtocolVersion, info.ConnectionID)
		return
	}

	fmt.Printf("{\"ok\":true,\"mysql\":true,\"protocol\":%d,\"server_version\":\"%s\",\"connection_id\":%d,"+
		"\"capability_flags\":%d,\"character_set\":%d,\"status_flags\":%d,\"auth_plugin\":\"%s\",\"preview_hex\":\"%s\"}\n",
		info.ProtocolVersion, escape(info.ServerVersion), info.ConnectionID,
		info.CapabilityFlags, info.CharacterSet, info.StatusFlags, escape(info.AuthPluginName), info.RawFirstBytesHex)
}