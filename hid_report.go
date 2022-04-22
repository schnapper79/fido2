package fido2

import "fmt"

type packet struct {
	CMD   uint8
	BCNTH uint8
	BCNTL uint8
	DATA  []byte
	seq   uint8
}

func (p *packet) ToReport() [][]byte {
	var result [][]byte
	result = make([][]byte, 0)
	length := uint16(len(p.DATA))
	p.BCNTL = uint8(length & 0xff)
	p.BCNTH = uint8((length >> 8) & 0xff)

	out := make([]byte, 0, int(report_size_in))
	out = append(out, byte(cid>>24), byte(cid>>16), byte(cid>>8), byte(cid&0xff))
	out = append(out, p.CMD|0x80)
	out = append(out, p.BCNTH, p.BCNTL)

	seq := uint8(0)
	for n := 0; n < len(p.DATA); n++ {
		out = append(out, p.DATA[n])

		if len(out) == int(report_size_in) {
			result = append(result, out)
			out = make([]byte, 0, int(report_size_in))
			out = append(out, byte(cid>>24), byte(cid>>16), byte(cid>>8), byte(cid&0xff))
			out = append(out, seq)
			seq++
		}
	}

	if len(out) != 5 {
		for n := len(out); n < int(report_size_in); n++ {
			out = append(out, 0)
		}
		result = append(result, out)
	}
	return result
}

func (p *packet) FromReport(in []byte) (bool, error) {
	CID := uint32(in[3]) | uint32(in[2])<<8 | uint32(in[1])<<16 | uint32(in[0])<<24
	if CID != cid {
		return false, fmt.Errorf("CID not match")
	}
	if in[4]&0x80 == 0 {
		//SEQ_PACKET

		seq_new := in[4]
		if seq_new != p.seq {
			return true, fmt.Errorf("SEQ_PACKET error")
		}
		p.seq++
		p.DATA = append(p.DATA, in[5:]...)
	} else {
		//CMD_PACKET
		cmd := in[4] & 0x7f
		switch cmd {
		case 0x3F: //error
			errString := ""
			switch in[7] {
			case 0x01:
				errString = "Invalid command"
			case 0x02:
				errString = "Invalid parameter"
			case 0x03:
				errString = "Invalid length"
			case 0x04:
				errString = "Invalid sequence"
			case 0x05:
				errString = "Msg timeout"
			case 0x06:
				errString = "Channel busy"
			case 0x0A:
				errString = "Command requires channel lock"
			case 0x0B:
				errString = "Invalid channel"
			case 0x7F:
				errString = "unspecific error"
			default:
				errString = "unknown error"
			}
			return false, fmt.Errorf("CMD_PACKET error: %s", errString)
		case 0x3B: //keepAlive

			return false, nil
		}
		p.CMD = cmd
		p.BCNTH = in[5]
		p.BCNTL = in[6]
		p.DATA = append(p.DATA, in[7:]...)
		p.seq = 0
	}
	if uint32(len(p.DATA)) < uint32(p.BCNTL)+uint32(p.BCNTH)<<8 {
		return false, nil //need more data
	}
	return true, nil //finally done

}
