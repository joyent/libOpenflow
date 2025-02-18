package openflow15

import (
	"encoding/binary"
)

/*
7.2.6.7 Set-Field Action Structure
The type of a set-field action is one of the valid OXM header types. The list of possible OXM types are described in Section 7.2.3.7 and Table 13. All header match fields are valid in the set-field action, except for OXM_OF_IPV6_EXTHDR. The pipeline fields OXM_OF_METADATA, OXM_OF_TUNNEL_ID and all OXM_OF_PKT_REG(N) are valid in the set-field action, other pipeline fields, OXM_OF_IN_PORT and OXM_OF_IN_PHY_PORT are not valid in the set-field action. The set-field action can include an Experimenter OXM field, the validity of Experimenter Set-Field actions is defined by the Experimenter OXM type itself

OXM_OF_IN_PORT is not valid for set_field
*/

// old style IN_PORT field
type NxmInportField struct {
	InPort uint16
}

func (m *NxmInportField) Len() uint16 {
	return 2
}
func (m *NxmInportField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 2)

	binary.BigEndian.PutUint16(data, m.InPort)
	return
}
func (m *NxmInportField) UnmarshalBinary(data []byte) error {
	m.InPort = binary.BigEndian.Uint16(data)
	return nil
}

// Return a MatchField for Input port matching
func NewNxmInportField(inPort uint16) *MatchField {
	f := new(MatchField)
	f.Class = OXM_CLASS_NXM_0
	f.Field = NXM_OF_IN_PORT
	f.HasMask = false

	inPortField := new(NxmInportField)
	inPortField.InPort = inPort
	f.Value = inPortField
	f.Length = uint8(inPortField.Len())

	return f
}
