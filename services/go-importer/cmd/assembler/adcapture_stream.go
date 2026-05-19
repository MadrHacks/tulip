// Copyright 2026 MadrHacks. Apache-2.0.
//
// REMOTE_CAPTURE_IP support: connect to an ad-capture broker and consume its
// pcap-NG-over-IP stream. Standard blocks (SHB, IDB, EPB, DSB, ...) are fed
// to the existing tulip pcap pipeline by writing them onto an os.Pipe; our
// own Custom Blocks (PEN=65535) carry decrypted SSL plaintext + 5-tuple
// metadata and become FlowEntries directly.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/gofrs/uuid/v5"

	"go-importer/internal/pkg/db"
)

// MadrHacks Private Enterprise Number (matches ad-capture's
// writers.MadrHacksCustomBlockPEN). IANA-reserved private-use slot.
const adCaptureCustomBlockPEN uint32 = 65535

// pcapng block type constants we care about.
const (
	ngBlockCustom         uint32 = 0x00000BAD
	ngBlockCustomNoncopy  uint32 = 0x40000BAD
	ngBlockSectionHeader  uint32 = 0x0A0D0D0A
	ngBlockEnhancedPacket uint32 = 6
)

// connectAdCaptureStream connects to addr (host:port) and streams pcap-NG
// blocks. Loops forever, reconnecting on disconnect with 5s backoff (matches
// the existing connectToPCAPOverIP behavior).
func connectAdCaptureStream(service *AssemblerService, addr string) {
	for {
		log.Println("ad-capture: dialing", addr)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Println("ad-capture: dial failed:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		sourceName := fmt.Sprintf("%s:%d", addr, time.Now().Unix())
		log.Println("ad-capture: connected", sourceName)

		// Pipe carries the standard pcap-NG blocks to tulip's existing pcap
		// reader. Custom Blocks are intercepted before they hit the pipe.
		pr, pw, perr := os.Pipe()
		if perr != nil {
			log.Println("ad-capture: pipe:", perr)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		// Goroutine: read TCP, split blocks, forward standard ones to pw,
		// decode our CBs into FlowEntries.
		go func() {
			defer pw.Close()
			defer conn.Close()
			if err := splitAdCaptureBlocks(conn, pw, service, sourceName); err != nil && err != io.EOF {
				log.Println("ad-capture: block split error:", err)
			}
			log.Println("ad-capture: stream closed", sourceName)
		}()

		// Drive tulip's existing pcap parser on the pipe read end.
		service.PcapOverIp = true
		service.HandlePcapFile(pr, sourceName)
		_ = pr.Close()
		time.Sleep(5 * time.Second)
	}
}

// splitAdCaptureBlocks reads pcap-NG blocks from src (the TCP connection),
// forwards standard blocks verbatim to passThrough (which feeds tulip's
// existing pcap parser), and intercepts our Custom Blocks, decoding them
// into FlowEntries on service.
func splitAdCaptureBlocks(src io.Reader, passThrough io.Writer, service *AssemblerService, sourceName string) error {
	// 8-byte block prefix: type (4) + total_length (4). All little-endian on
	// our wire (ad-capture writes LE).
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(src, hdr); err != nil {
			return err
		}
		blockType := binary.LittleEndian.Uint32(hdr[0:4])
		totalLen := binary.LittleEndian.Uint32(hdr[4:8])
		if totalLen < 12 {
			return fmt.Errorf("invalid pcap-NG block length %d", totalLen)
		}
		bodyLen := int(totalLen) - 8 // remaining bytes after type+length prefix
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(src, body); err != nil {
			return err
		}
		// Custom Block (copyable or non-copyable): intercept.
		if blockType == ngBlockCustom || blockType == ngBlockCustomNoncopy {
			if len(body) < 4 {
				continue
			}
			pen := binary.LittleEndian.Uint32(body[0:4])
			if pen == adCaptureCustomBlockPEN {
				// payload = body[4:] minus trailing 4-byte length echo and
				// any 0-3 padding bytes between the body and the trailing
				// length. We can reconstruct: the actual payload length is
				// encoded in our CustomBlockPayloadV1.payload_len field;
				// so just parse from body[4:].
				if err := handleAdCaptureCustomBlock(body[4:], service, sourceName); err != nil {
					log.Println("ad-capture: CB decode warn:", err)
				}
				// Do NOT forward this block to the standard parser — libpcap
				// would silently drop it but we save the work.
				continue
			}
			// Unknown PEN: drop silently (don't forward either; tulip
			// wouldn't know what to do with it).
			continue
		}
		// Standard block: forward verbatim (prefix + body) to the parser.
		if _, err := passThrough.Write(hdr); err != nil {
			return err
		}
		if _, err := passThrough.Write(body); err != nil {
			return err
		}
	}
}

// CustomBlockPayloadV1 mirrors writers.CustomBlockPayloadV1 in ad-capture.
// Keep these two structs in lockstep (eventually move to a shared module).
type adCapturePayloadV1 struct {
	Version    uint8
	IPFamily   uint8 // 4 or 6 or 0 if unknown
	Direction  uint8 // 0=client_to_server (SSL_write), 1=server_to_client (SSL_read)
	Reserved   uint8
	Pid        uint32
	Comm       [16]byte
	SrcIP      [16]byte
	DstIP      [16]byte
	SrcPort    uint16
	DstPort    uint16
	TLSVersion uint32
	Timestamp  uint64
	PayloadLen uint32
	Payload    []byte
}

const adCapturePayloadHeaderSize = 1 + 1 + 1 + 1 + 4 + 16 + 16 + 16 + 2 + 2 + 4 + 8 + 4

func decodeAdCapturePayload(b []byte) (*adCapturePayloadV1, error) {
	if len(b) < adCapturePayloadHeaderSize {
		return nil, fmt.Errorf("payload too short (%d < %d)", len(b), adCapturePayloadHeaderSize)
	}
	r := bytes.NewReader(b)
	p := &adCapturePayloadV1{}
	if err := binary.Read(r, binary.LittleEndian, &p.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.IPFamily); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.Direction); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.Reserved); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.Pid); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, p.Comm[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, p.SrcIP[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, p.DstIP[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.SrcPort); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.DstPort); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.TLSVersion); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &p.PayloadLen); err != nil {
		return nil, err
	}
	if int(p.PayloadLen) > r.Len() {
		return nil, errors.New("payload_len exceeds buffer")
	}
	p.Payload = make([]byte, p.PayloadLen)
	if _, err := io.ReadFull(r, p.Payload); err != nil {
		return nil, err
	}
	return p, nil
}

// handleAdCaptureCustomBlock decodes one of our CBs and writes a FlowEntry to
// the DB. We coalesce per (pid, src_ip:src_port → dst_ip:dst_port) into a
// short-lived bucket in the future; for v1, each SSL_read/SSL_write event
// becomes its own one-chunk flow tagged tls-decrypted. Tulip's UI groups by
// 5-tuple, so they'll cluster naturally on the front-end.
func handleAdCaptureCustomBlock(body []byte, service *AssemblerService, sourceName string) error {
	p, err := decodeAdCapturePayload(body)
	if err != nil {
		return err
	}
	if p.PayloadLen == 0 {
		return nil
	}
	log.Printf("ad-capture: CB pid=%d comm=%s %v:%d->%v:%d dir=%d %d bytes",
		p.Pid, bytes.TrimRight(p.Comm[:], "\x00"),
		addrFromBytes(p.IPFamily, p.SrcIP), p.SrcPort,
		addrFromBytes(p.IPFamily, p.DstIP), p.DstPort,
		p.Direction, p.PayloadLen)
	src, dst := addrFromBytes(p.IPFamily, p.SrcIP), addrFromBytes(p.IPFamily, p.DstIP)
	from := "c" // c→s
	if p.Direction == 1 {
		from = "s" // s→c
	}
	flowID := uuidV4()
	flow := db.FlowEntry{
		Id:          flowID,
		Src_port:    p.SrcPort,
		Dst_port:    p.DstPort,
		Src_ip:      src,
		Dst_ip:      dst,
		Time:        time.Unix(0, int64(p.Timestamp)),
		Duration:    0,
		Filename:    sourceName,
		Num_packets: 1,
		Size:        int(p.PayloadLen),
		Tags:        []string{"tls-decrypted"},
		Flow: []db.FlowItem{{
			Id:     uuidV4(),
			FlowId: flowID,
			Kind:   "raw",
			From:   from,
			Data:   p.Payload,
			Time:   time.Unix(0, int64(p.Timestamp)),
		}},
	}
	// Use the same callback the existing reassembly path uses — gets the
	// flow into the DB plus tag handling, flag detection, etc.
	reassemblyCallback(flow)
	return nil
}

// uuidV4 is a tiny wrapper around gofrs/uuid.NewV4 that swallows the error;
// gofrs's API returns (UUID, error) but we never want a failing UUID for our
// own bookkeeping. Behavior on RNG failure: zero UUID (extremely unlikely).
func uuidV4() uuid.UUID {
	id, _ := uuid.NewV4()
	return id
}

// addrFromBytes converts a 16-byte address slot (IPv4-in-IPv6 mapping in the
// first 4 bytes when family=4; full v6 otherwise) into a netip.Addr.
func addrFromBytes(family uint8, b [16]byte) netip.Addr {
	switch family {
	case 4:
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	case 6:
		return netip.AddrFrom16(b)
	default:
		// Heuristic: if last 12 bytes are zero, treat as v4; else v6.
		isV4 := true
		for i := 4; i < 16; i++ {
			if b[i] != 0 {
				isV4 = false
				break
			}
		}
		if isV4 {
			return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
		}
		return netip.AddrFrom16(b)
	}
}
