package openflow15

import (
	"encoding/binary"
	"errors"
	"fmt"

	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/util"
)

// ofp_action_type 1.5
const (
	ActionType_Output     = 0
	ActionType_CopyTtlOut = 11
	ActionType_CopyTtlIn  = 12
	ActionType_SetMplsTtl = 15
	ActionType_DecMplsTtl = 16
	ActionType_PushVlan   = 17
	ActionType_PopVlan    = 18
	ActionType_PushMpls   = 19
	ActionType_PopMpls    = 20
	ActionType_SetQueue   = 21
	ActionType_Group      = 22
	ActionType_SetNwTtl   = 23
	ActionType_DecNwTtl   = 24
	ActionType_SetField   = 25
	ActionType_PushPbb    = 26
	ActionType_PopPbb     = 27
	ActionType_Copy_Field = 28
	ActionType_Meter      = 29

	ActionType_Experimenter = 0xffff
)

type Action interface {
	Header() *ActionHeader
	util.Message
}

type ActionHeader struct {
	Type   uint16
	Length uint16
}

func (a *ActionHeader) Header() *ActionHeader {
	return a
}

func (a *ActionHeader) Len() (n uint16) {
	return 4
}

func (a *ActionHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	binary.BigEndian.PutUint16(data[:2], a.Type)
	binary.BigEndian.PutUint16(data[2:4], a.Length)
	return
}

func (a *ActionHeader) UnmarshalBinary(data []byte) error {
	if len(data) < int(a.Len()) {
		return errors.New("The []byte the wrong size to unmarshal an " +
			"ActionHeader message.")
	}
	a.Type = binary.BigEndian.Uint16(data[:2])
	a.Length = binary.BigEndian.Uint16(data[2:4])
	return nil
}

// Decode Action types.
func DecodeAction(data []byte) (Action, error) {
	t := binary.BigEndian.Uint16(data[:2])
	var a Action
	var err error
	switch t {
	case ActionType_Output:
		a = new(ActionOutput)
	case ActionType_CopyTtlOut:
		a = new(ActionHeader)
	case ActionType_CopyTtlIn:
		a = new(ActionHeader)
	case ActionType_SetMplsTtl:
		a = new(ActionMplsTtl)
	case ActionType_DecMplsTtl:
		a = new(ActionHeader)
	case ActionType_PushVlan:
		a = new(ActionPush)
	case ActionType_PopVlan:
		a = new(ActionPopVlan)
	case ActionType_PushMpls:
		a = new(ActionPush)
	case ActionType_PopMpls:
		a = new(ActionPopMpls)
	case ActionType_SetQueue:
		a = new(ActionSetqueue)
	case ActionType_Group:
		a = new(ActionGroup)
	case ActionType_SetNwTtl:
		a = new(ActionNwTtl)
	case ActionType_DecNwTtl:
		a = new(ActionDecNwTtl)
	case ActionType_SetField:
		a = new(ActionSetField)
	case ActionType_PushPbb:
		a = new(ActionPush)
	case ActionType_PopPbb:
		a = new(ActionHeader)
	case ActionType_Copy_Field:
		a = new(ActionCopyField)
	case ActionType_Meter:
		a = new(ActionMeter)
	case ActionType_Experimenter:
		// For Experimenter message, the length of action should be at least 10 bytes,
		// including type(2 byte), length(2 byte), vendor(4 byte), and subtype(2 byte)
		if len(data) < NxActionHeaderLength {
			return nil, errors.New("the []byte is too short to decode OpenFlow experimenter message")
		}
		v := binary.BigEndian.Uint32(data[4:8])
		if v == NxExperimenterID {
			a, err = DecodeNxAction(data)
			if err != nil {
				//klog.ErrorS(err, "Failed to decode NxAction", "data", data)
				err = fmt.Errorf("Failed to decode NxAction: err=%v, %v", err, data)
				return nil, err
			} else if a == nil {
				err = fmt.Errorf("Failed to decode NxAction: no supported action, %v", data)
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("DecodeAction unknown type: %v", t)
	}

	if a == nil {
		return nil, fmt.Errorf("DecodeAction unknown type: %v", t)
	}

	err = a.UnmarshalBinary(data)
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal", "structure", a, "data", data)
		return a, err
	}
	return a, nil
}

// Action structure for OFPAT_OUTPUT, which sends packets out ’port’.
// When the ’port’ is the OFPP_CONTROLLER, ’max_len’ indicates the max
// number of bytes to send. A ’max_len’ of zero means no bytes of the
// packet should be sent.
type ActionOutput struct {
	ActionHeader
	Port   uint32
	MaxLen uint16
	pad    []byte // 6 bytes to make it 64bit aligned
}

// ofp_controller_max_len
const (
	OFPCML_MAX       = 0xffe5 /* maximum max_len value which can be used to request a specific byte length. */
	OFPCML_NO_BUFFER = 0xffff /* indicates that no buffering should be applied and the whole packet is to be sent to the controller. */
)

// Returns a new Action Output message which sends packets out
// port number.
func NewActionOutput(portNum uint32) *ActionOutput {
	act := new(ActionOutput)
	act.Type = ActionType_Output
	act.Length = act.Len()
	act.Port = portNum
	act.MaxLen = OFPCML_NO_BUFFER
	act.pad = make([]byte, 6)
	return act
}

func (a *ActionOutput) Len() (n uint16) {
	return a.ActionHeader.Len() + 12
}

func (a *ActionOutput) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	var b []byte
	n := 0

	b, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint32(data[n:], a.Port)
	n += 4
	binary.BigEndian.PutUint16(data[n:], a.MaxLen)
	n += 2
	copy(data[n:], a.pad)
	n += len(a.pad)

	return
}

func (a *ActionOutput) UnmarshalBinary(data []byte) error {
	if len(data) < int(a.Len()) {
		return errors.New("The []byte the wrong size to unmarshal an " +
			"ActionOutput message.")
	}
	n := 0
	err := a.ActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(a.ActionHeader.Len())
	a.Port = binary.BigEndian.Uint32(data[n:])
	n += 4
	a.MaxLen = binary.BigEndian.Uint16(data[n:])
	n += 2
	copy(a.pad, data[n:n+6])
	n += 6
	return err
}

type ActionSetqueue struct {
	ActionHeader
	QueueId uint32
}

func NewActionSetQueue(queue uint32) *ActionSetqueue {
	a := new(ActionSetqueue)
	a.Type = ActionType_SetQueue
	a.Length = a.Len()
	a.QueueId = queue
	return a
}

func (a *ActionSetqueue) Len() (n uint16) {
	return a.ActionHeader.Len() + 4
}

func (a *ActionSetqueue) MarshalBinary() (data []byte, err error) {
	data, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes[0:], a.QueueId)

	data = append(data, bytes...)
	return
}

func (a *ActionSetqueue) UnmarshalBinary(data []byte) error {
	if len(data) != int(a.Len()) {
		return errors.New("The []byte the wrong size to unmarshal an " +
			"ActionEnqueue message.")
	}
	a.ActionHeader.UnmarshalBinary(data[:4])
	a.QueueId = binary.BigEndian.Uint32(data[4:8])
	return nil
}

type ActionGroup struct {
	ActionHeader
	GroupId uint32
}

func NewActionGroup(group uint32) *ActionGroup {
	a := new(ActionGroup)
	a.Type = ActionType_Group
	a.Length = a.Len()
	a.GroupId = group
	return a
}

func (a *ActionGroup) Len() (n uint16) {
	return a.ActionHeader.Len() + 4
}

func (a *ActionGroup) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	var b []byte
	n := 0

	b, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint32(data[n:], a.GroupId)
	n += 4

	return
}

func (a *ActionGroup) UnmarshalBinary(data []byte) error {
	if len(data) < int(a.Len()) {
		return errors.New("The []byte the wrong size to unmarshal an " +
			"ActionOutput message.")
	}
	n := 0
	err := a.ActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(a.ActionHeader.Len())
	a.GroupId = binary.BigEndian.Uint32(data[n:])
	n += 4

	return err
}

type ActionMplsTtl struct {
	ActionHeader
	MplsTtl uint8
}

func (a *ActionMplsTtl) Len() uint16 {
	return a.ActionHeader.Len() + 4
}

func (a *ActionMplsTtl) MarshalBinary() (data []byte, err error) {
	data, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}
	n := int(a.ActionHeader.Len())
	data[n] = a.MplsTtl
	return
}

func (a *ActionMplsTtl) UnmarshalBinary(data []byte) error {
	n := 0
	err := a.ActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(a.ActionHeader.Len())
	a.MplsTtl = data[n]
	return nil
}

type ActionDecNwTtl struct {
	ActionHeader
	pad []byte // 4bytes
}

func NewActionDecNwTtl() *ActionDecNwTtl {
	act := new(ActionDecNwTtl)
	act.Type = ActionType_DecNwTtl
	act.Length = act.Len()
	act.pad = make([]byte, 4)
	return act
}

func (a *ActionDecNwTtl) Len() (n uint16) {
	return a.ActionHeader.Len() + 4
}

func (a *ActionDecNwTtl) MarshalBinary() (data []byte, err error) {
	data, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}

	// Padding
	bytes := make([]byte, 4)
	data = append(data, bytes...)
	return
}

func (a *ActionDecNwTtl) UnmarshalBinary(data []byte) error {
	return a.ActionHeader.UnmarshalBinary(data[:4])
}

type ActionNwTtl struct {
	ActionHeader
	NwTtl uint8
}

func (a *ActionNwTtl) Len() uint16 {
	return a.ActionHeader.Len() + 4
}

func (a *ActionNwTtl) MarshalBinary() (data []byte, err error) {
	data, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}
	n := int(a.ActionHeader.Len())
	data[n] = a.NwTtl
	return
}

func (a *ActionNwTtl) UnmarshalBinary(data []byte) error {
	n := 0
	err := a.ActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(a.ActionHeader.Len())
	a.NwTtl = data[n]
	return nil
}

type ActionPush struct {
	ActionHeader
	EtherType uint16
}

func NewActionPushVlan(etherType uint16) *ActionPush {
	a := new(ActionPush)
	a.Type = ActionType_PushVlan
	a.Length = a.Len()
	a.EtherType = etherType
	return a
}

func NewActionPushMpls(etherType uint16) *ActionPush {
	a := new(ActionPush)
	a.Type = ActionType_PushMpls
	a.Length = a.Len()
	a.EtherType = etherType
	return a
}

func (a *ActionPush) Len() (n uint16) {
	return a.ActionHeader.Len() + 4
}

func (a *ActionPush) MarshalBinary() (data []byte, err error) {
	data, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 4)
	binary.BigEndian.PutUint16(bytes[0:], a.EtherType)

	data = append(data, bytes...)
	return
}

func (a *ActionPush) UnmarshalBinary(data []byte) error {
	a.ActionHeader.UnmarshalBinary(data[:4])
	a.EtherType = binary.BigEndian.Uint16(data[4:])
	return nil
}

type ActionPopVlan struct {
	ActionHeader
}

func NewActionPopVlan() *ActionPopVlan {
	act := new(ActionPopVlan)
	act.Type = ActionType_PopVlan
	act.Length = act.Len()

	return act
}

func (a *ActionPopVlan) Len() (n uint16) {
	return a.ActionHeader.Len() + 4
}

func (a *ActionPopVlan) MarshalBinary() (data []byte, err error) {
	data, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}

	// Padding
	bytes := make([]byte, 4)

	data = append(data, bytes...)
	return
}

func (a *ActionPopVlan) UnmarshalBinary(data []byte) error {
	a.ActionHeader.UnmarshalBinary(data[:4])
	return nil
}

type ActionPopMpls struct {
	ActionHeader
	EtherType uint16
}

func NewActionPopMpls(etherType uint16) *ActionPopMpls {
	act := new(ActionPopMpls)
	act.Type = ActionType_PopMpls
	act.EtherType = etherType
	act.Length = act.Len()

	return act
}

func (a *ActionPopMpls) Len() (n uint16) {
	return a.ActionHeader.Len() + 4
}

func (a *ActionPopMpls) MarshalBinary() (data []byte, err error) {
	data, err = a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}

	// Padding
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint16(bytes[0:], a.EtherType)

	data = append(data, bytes...)
	return
}

func (a *ActionPopMpls) UnmarshalBinary(data []byte) error {
	a.ActionHeader.UnmarshalBinary(data[:4])
	a.EtherType = binary.BigEndian.Uint16(data[4:])
	return nil
}

type ActionSetField struct {
	ActionHeader
	Field MatchField
}

func NewActionSetField(field MatchField) *ActionSetField {
	a := new(ActionSetField)
	a.Type = ActionType_SetField
	a.Field = field
	a.Length = a.Len()
	return a
}

func (a *ActionSetField) Len() (n uint16) {
	n = a.ActionHeader.Len() + a.Field.Len()
	// Round it to closest multiple of 8
	n = ((n + 7) / 8) * 8

	return
}

func (a *ActionSetField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	n := 0
	b, err := a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, b)
	n += int(a.ActionHeader.Len())

	b, err = a.Field.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)

	return
}

func (a *ActionSetField) UnmarshalBinary(data []byte) error {
	n := 0
	err := a.ActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(a.ActionHeader.Len())
	err = a.Field.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(a.Field.Len())

	return err
}

// ofp_action_copy_field
type ActionCopyField struct {
	ActionHeader
	NBits     uint16
	SrcOffset uint16
	DstOffset uint16
	Pad       uint16
	OxmIdSrc  OxmId
	OxmIdDst  OxmId
}

func NewActionCopyField(nBits uint16, srcOffset uint16, dstOffset uint16,
	srcOxmId OxmId, dstOxmId OxmId) *ActionCopyField {
	a := new(ActionCopyField)
	a.Type = ActionType_Copy_Field
	a.Length = a.Len()
	a.NBits = nBits
	a.SrcOffset = srcOffset
	a.DstOffset = dstOffset
	a.OxmIdSrc = srcOxmId
	a.OxmIdDst = dstOxmId
	return a
}

func (a *ActionCopyField) Len() (n uint16) {
	n = a.ActionHeader.Len() + 8
	n += a.OxmIdSrc.Len()
	n += a.OxmIdDst.Len()
	// Round it to closest multiple of 8
	n = ((n + 7) / 8) * 8

	return
}

func (a *ActionCopyField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	var n uint16
	b, err := a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, b)
	n += a.ActionHeader.Len()

	binary.BigEndian.PutUint16(data[n:], a.NBits)
	n += 2

	binary.BigEndian.PutUint16(data[n:], a.SrcOffset)
	n += 2

	binary.BigEndian.PutUint16(data[n:], a.DstOffset)
	n += 2

	// Extra 2 bytes for Pad
	n += 2

	b, err = a.OxmIdSrc.MarshalBinary()
	if err != nil {
		return data, err
	}
	copy(data[n:], b)
	n += a.OxmIdSrc.Len()

	b, err = a.OxmIdDst.MarshalBinary()
	if err != nil {
		return data, err
	}
	copy(data[n:], b)
	n += a.OxmIdDst.Len()

	return
}

func (a *ActionCopyField) UnmarshalBinary(data []byte) error {
	var n uint16
	err := a.ActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += a.ActionHeader.Len()

	a.NBits = binary.BigEndian.Uint16(data[n:])
	n += 2

	a.SrcOffset = binary.BigEndian.Uint16(data[n:])
	n += 2

	a.DstOffset = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2 // Pad

	err = a.OxmIdSrc.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += a.OxmIdSrc.Len()

	err = a.OxmIdDst.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += a.OxmIdDst.Len()

	return err
}

// ofp_action_meter
type ActionMeter struct {
	ActionHeader
	MeterId uint32
}

func NewActionMeter(meterId uint32) *ActionMeter {
	a := new(ActionMeter)
	a.Type = ActionType_Meter
	a.Length = a.Len()
	a.MeterId = meterId
	return a
}

func (a *ActionMeter) Len() (n uint16) {
	n = a.ActionHeader.Len() + 4

	return
}

func (a *ActionMeter) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	n := 0
	b, err := a.ActionHeader.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, b)
	n += int(a.ActionHeader.Len())

	binary.BigEndian.PutUint32(data[n:], a.MeterId)

	return
}
func (a *ActionMeter) UnmarshalBinary(data []byte) error {
	n := 0
	err := a.ActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(a.ActionHeader.Len())

	a.MeterId = binary.BigEndian.Uint32(data[n:])
	n += 4

	return err
}
