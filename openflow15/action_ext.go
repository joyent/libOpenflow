package openflow15

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
// Action structure for NXAST_ENCAP
// see more details: openvswitch-2.17.8/include/openvswitch/ofp-ed-props.h

struct nx_action_encap {
    ovs_be16 type;         // OFPAT_VENDOR.
    ovs_be16 len;          // Total size including any property TLVs.
    ovs_be32 vendor;       // NX_VENDOR_ID.
    ovs_be16 subtype;      // NXAST_ENCAP.
    ovs_be16 hdr_size;     // Header size in bytes, 0 = 'not specified'.
    ovs_be32 new_pkt_type; // Header type to add and PACKET_TYPE of result.
    struct ofp_ed_prop_header props[];  // Encap TLV properties.
};
OFP_ASSERT(sizeof(struct nx_action_encap) == 16);

//
// External representation of encap/decap properties.
// These must be padded to a multiple of 8 bytes.
//
struct ofp_ed_prop_header {
    ovs_be16 prop_class;
    uint8_t type;
    uint8_t len;
};

struct ofp_ed_prop_nsh_md_type {
    struct ofp_ed_prop_header header;
    uint8_t md_type;         // NSH MD type .
    uint8_t pad[3];          // Padding to 8 bytes.
};

struct ofp_ed_prop_nsh_tlv {
    struct ofp_ed_prop_header header;
    ovs_be16 tlv_class;      // Metadata class.
    uint8_t tlv_type;        // Metadata type including C bit.
    uint8_t tlv_len;         // Metadata value length (0-127).

    // tlv_len octets of metadata value, padded to a multiple of 8 bytes.
    uint8_t data[0];
};
*/

const (
	ENCAP_PKT_TYPE_ETHERNET = 0
	ENCAP_PKT_TYPE_MPLS     = 1<<16 | 0x8847
	ENCAP_PKT_TYPE_MPLS_MC  = 1<<16 | 0x8848
	ENCAP_PKT_TYPE_NSH      = 1<<16 | 0x894f
)

type NXActionEncap struct {
	*NXActionHeader
	HeaderSize uint16
	PacketType uint32
}

func (a *NXActionEncap) Len() (n uint16) {
	return a.Length
}

func (a *NXActionEncap) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	var b []byte
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)

	binary.BigEndian.PutUint16(data[n:], a.HeaderSize)
	n += 2

	binary.BigEndian.PutUint32(data[n:], a.PacketType)
	n += 4

	return
}

func (a *NXActionEncap) UnmarshalBinary(data []byte) error {
	return fmt.Errorf("NXActionEncap.UnmarshalBinary is not implemted")
}

func NewNXActionEncap(pktType uint32) *NXActionEncap {
	a := &NXActionEncap{
		NXActionHeader: NewNxActionHeader(NXAST_RAW_ENCAP),
		PacketType:     pktType,
	}

	a.Length = 16
	return a
}

func NewNXActionDecap(pktType uint32) *NXActionEncap {
	a := &NXActionEncap{
		NXActionHeader: NewNxActionHeader(NXAST_RAW_DECAP),
		PacketType:     pktType,
	}

	a.Length = 16
	return a
}

/*
struct nx_action_stack {
    ovs_be16 type;                  // OFPAT_VENDOR.
    ovs_be16 len;                   // Length is 16.
    ovs_be32 vendor;                // NX_VENDOR_ID.
    ovs_be16 subtype;               // NXAST_STACK_PUSH or NXAST_STACK_POP.
    ovs_be16 offset;                // Bit offset into the field.
    // Followed by:
    //- OXM/NXM header for field to push or pop (4 or 8 bytes).
    // - ovs_be16 'n_bits', the number of bits to extract from the field.
    // - Enough 0-bytes to pad out the action to 24 bytes.

    //uint8_t pad[12];                // See above.
};
*/

type NXActionStack struct {
	*NXActionHeader
	OfsNbits uint16      // Bit offset into the field.
	SrcField *MatchField // OXM/NXM header for field to push or pop (4 or 8 bytes)
	Nbits    uint16      // the number of bits to extract from the field.
	zero     [6]uint8    // 6 uint8 with all Value as 0, reserved, to 24 bytes
}

func (a *NXActionStack) Len() (n uint16) {
	return a.Length
}

func (a *NXActionStack) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	var b []byte
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.OfsNbits)
	n += 2
	fieldHeaderData := a.SrcField.MarshalHeader()
	binary.BigEndian.PutUint32(data[n:], fieldHeaderData)
	n += 4
	binary.BigEndian.PutUint16(data[n:], a.Nbits)
	n += 2
	copy(data[n:], a.zero[0:])
	n += 6

	return
}

func (a *NXActionStack) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	if err := a.NXActionHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the []byte is too short to unmarshal a full NXActionStack message")
	}
	a.OfsNbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.SrcField = new(MatchField)
	if err := a.SrcField.UnmarshalHeader(data[n : n+4]); err != nil {
		err = fmt.Errorf("Failed to unmarshal NXActionStack's SrcField, err=%s, data=%v", err, data[n:n+4])
		return err
	}

	n += 4
	a.Nbits = binary.BigEndian.Uint16(data[n:])

	return nil
}

func newNXActionStack(act uint16) *NXActionStack {
	a := &NXActionStack{
		NXActionHeader: NewNxActionHeader(act),
		zero:           [6]uint8{},
	}
	a.Length = 24
	return a
}

func NewNXActionStackPush(srcField *MatchField, nBits uint16) *NXActionStack {
	a := &NXActionStack{
		NXActionHeader: NewNxActionHeader(NXAST_STACK_PUSH),
		zero:           [6]uint8{},
	}
	a.Length = 24
	a.SrcField = srcField
	a.Nbits = nBits

	return a
}

func NewNXActionStackPop(srcField *MatchField, nBits uint16) *NXActionStack {
	a := &NXActionStack{
		NXActionHeader: NewNxActionHeader(NXAST_STACK_POP),
		zero:           [6]uint8{},
	}
	a.Length = 24
	a.SrcField = srcField
	a.Nbits = nBits

	return a
}

type MplsTtlField struct {
	Ttl uint8
}

func (m *MplsTtlField) Len() uint16 {
	return 1
}

func (m *MplsTtlField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 1)
	data[0] = m.Ttl
	return
}

func (m *MplsTtlField) UnmarshalBinary(data []byte) error {
	if len(data) < int(m.Len()) {
		return fmt.Errorf("the []byte is too short to unmarshal a full Mpls TtlField message")
	}
	m.Ttl = data[0]
	return nil
}

// NewMplsTtlField will return a MatchField for mpls ttl
func NewMplsTtlField(ttl uint8) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_NXM_1
	f.Field = NXM_NX_MPLS_TTL
	f.HasMask = false

	ttlField := new(MplsTtlField)
	ttlField.Ttl = ttl
	f.Value = ttlField
	f.Length = uint8(ttlField.Len())

	return f
}

/*
type NXActionCtClear struct {
	*NXActionHeader
}

func (a *NXActionCtClear) Len() (n uint16) {
	return a.Length
}

func (a *NXActionCtClear) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	var b []byte
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)

	return
}

func (a *NXActionCtClear) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	if err := a.NXActionHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}

	return nil
}

func NewNXActionCtClear() *NXActionCtClear {
	a := &NXActionCtClear{
		NXActionHeader: NewNxActionHeader(NXAST_CT_CLEAR),
	}

	//a.Length = a.NXActionHeader.Len()

	return a
}
*/
