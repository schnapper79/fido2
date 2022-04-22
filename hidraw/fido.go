package hidraw

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"
)

func FindFIDO() (*HidDevice, error) {
	paths, err := getHIDPaths()
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		h, err := NewHidDevice(path)
		if err != nil {
			continue
		}
		ok, err := h.IsFido()
		if err != nil {
			continue
		}
		if ok {
			cid = 0xffffffff
			return h, nil
		}
	}
	return nil, fmt.Errorf("no FIDO device found")
}

func (h *HidDevice) sendCMD(cmd *PACKET) error {
	reports := cmd.ToReport()
	for _, report := range reports {
		_, err := h.Write(report)
		//fmt.Printf("--> %x\n", report)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *HidDevice) rcvCMD() (*PACKET, error) {
	answer := &PACKET{}
	defer time.Sleep(50 * time.Millisecond)
	for {
		report := make([]byte, report_size_out)
		n, err := h.Read(report)
		if err != nil {
			return nil, err
		}
		if n != int(report_size_out) {
			return nil, fmt.Errorf("read report size not match")
		}
		//fmt.Printf("	<-- %x\n", report)
		done, err := answer.FromReport(report)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
	}
	return answer, nil
}

func (h *HidDevice) SendAndReceive(cmd uint8, data []byte) ([]byte, error) {
	cmdPacket := &PACKET{
		CMD:  cmd,
		DATA: data,
	}
	err := h.sendCMD(cmdPacket)
	if err != nil {
		return nil, err
	}
	answer, err := h.rcvCMD()
	if err != nil {
		return nil, err
	}
	if (answer.CMD & 0x7f) != cmd {
		return nil, fmt.Errorf("cmd not match")
	}
	return answer.DATA, nil
}

func (h *HidDevice) SetNewCID(newCid uint32) {
	cid = newCid
}
func getHIDPaths() ([]string, error) {
	paths := []string{}
	files, err := ioutil.ReadDir("/dev")
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if strings.HasPrefix(f.Name(), "hidraw") {
			paths = append(paths, "/dev/"+f.Name())
		}
	}

	return paths, nil
}
