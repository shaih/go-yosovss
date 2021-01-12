package pedersen

// Code generated by github.com/tinylib/msgp DO NOT EDIT.

import (
	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *Params) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, err = dc.ReadMapHeader()
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "G":
			err = z.G.DecodeMsg(dc)
			if err != nil {
				err = msgp.WrapError(err, "G")
				return
			}
		case "H":
			err = z.H.DecodeMsg(dc)
			if err != nil {
				err = msgp.WrapError(err, "H")
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *Params) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 2
	// write "G"
	err = en.Append(0x82, 0xa1, 0x47)
	if err != nil {
		return
	}
	err = z.G.EncodeMsg(en)
	if err != nil {
		err = msgp.WrapError(err, "G")
		return
	}
	// write "H"
	err = en.Append(0xa1, 0x48)
	if err != nil {
		return
	}
	err = z.H.EncodeMsg(en)
	if err != nil {
		err = msgp.WrapError(err, "H")
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *Params) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 2
	// string "G"
	o = append(o, 0x82, 0xa1, 0x47)
	o, err = z.G.MarshalMsg(o)
	if err != nil {
		err = msgp.WrapError(err, "G")
		return
	}
	// string "H"
	o = append(o, 0xa1, 0x48)
	o, err = z.H.MarshalMsg(o)
	if err != nil {
		err = msgp.WrapError(err, "H")
		return
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Params) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "G":
			bts, err = z.G.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "G")
				return
			}
		case "H":
			bts, err = z.H.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "H")
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *Params) Msgsize() (s int) {
	s = 1 + 2 + z.G.Msgsize() + 2 + z.H.Msgsize()
	return
}

// DecodeMsg implements msgp.Decodable
func (z *Share) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, err = dc.ReadMapHeader()
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "index":
			z.Index, err = dc.ReadInt()
			if err != nil {
				err = msgp.WrapError(err, "Index")
				return
			}
		case "index_scalar":
			err = z.IndexScalar.DecodeMsg(dc)
			if err != nil {
				err = msgp.WrapError(err, "IndexScalar")
				return
			}
		case "s":
			err = z.S.DecodeMsg(dc)
			if err != nil {
				err = msgp.WrapError(err, "S")
				return
			}
		case "r":
			err = z.R.DecodeMsg(dc)
			if err != nil {
				err = msgp.WrapError(err, "R")
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *Share) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 4
	// write "index"
	err = en.Append(0x84, 0xa5, 0x69, 0x6e, 0x64, 0x65, 0x78)
	if err != nil {
		return
	}
	err = en.WriteInt(z.Index)
	if err != nil {
		err = msgp.WrapError(err, "Index")
		return
	}
	// write "index_scalar"
	err = en.Append(0xac, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x5f, 0x73, 0x63, 0x61, 0x6c, 0x61, 0x72)
	if err != nil {
		return
	}
	err = z.IndexScalar.EncodeMsg(en)
	if err != nil {
		err = msgp.WrapError(err, "IndexScalar")
		return
	}
	// write "s"
	err = en.Append(0xa1, 0x73)
	if err != nil {
		return
	}
	err = z.S.EncodeMsg(en)
	if err != nil {
		err = msgp.WrapError(err, "S")
		return
	}
	// write "r"
	err = en.Append(0xa1, 0x72)
	if err != nil {
		return
	}
	err = z.R.EncodeMsg(en)
	if err != nil {
		err = msgp.WrapError(err, "R")
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *Share) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 4
	// string "index"
	o = append(o, 0x84, 0xa5, 0x69, 0x6e, 0x64, 0x65, 0x78)
	o = msgp.AppendInt(o, z.Index)
	// string "index_scalar"
	o = append(o, 0xac, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x5f, 0x73, 0x63, 0x61, 0x6c, 0x61, 0x72)
	o, err = z.IndexScalar.MarshalMsg(o)
	if err != nil {
		err = msgp.WrapError(err, "IndexScalar")
		return
	}
	// string "s"
	o = append(o, 0xa1, 0x73)
	o, err = z.S.MarshalMsg(o)
	if err != nil {
		err = msgp.WrapError(err, "S")
		return
	}
	// string "r"
	o = append(o, 0xa1, 0x72)
	o, err = z.R.MarshalMsg(o)
	if err != nil {
		err = msgp.WrapError(err, "R")
		return
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Share) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "index":
			z.Index, bts, err = msgp.ReadIntBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Index")
				return
			}
		case "index_scalar":
			bts, err = z.IndexScalar.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "IndexScalar")
				return
			}
		case "s":
			bts, err = z.S.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "S")
				return
			}
		case "r":
			bts, err = z.R.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "R")
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *Share) Msgsize() (s int) {
	s = 1 + 6 + msgp.IntSize + 13 + z.IndexScalar.Msgsize() + 2 + z.S.Msgsize() + 2 + z.R.Msgsize()
	return
}
