package hidraw

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

var (
	report_size_in  uint16 = 64
	report_size_out uint16 = 64
	cid             uint32 = 0xFFFFFFFF
)

type HidDevice struct {
	handle *os.File
}

func NewHidDevice(path string) (*HidDevice, error) {
	h := &HidDevice{
		handle: nil,
	}
	var err error
	h.handle, err = os.OpenFile(path, os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	return h, nil
}
func (h *HidDevice) Close() error {
	return h.handle.Close()
}
func (h *HidDevice) Write(buf []byte) (int, error) {
	return h.handle.Write(buf)
}
func (h *HidDevice) Read(buf []byte) (int, error) {
	return h.handle.Read(buf)
}
func (h *HidDevice) SetReportSize() error {
	if h.handle == nil {
		return fmt.Errorf("handle is nil")
	}
	l, err := unix.IoctlGetInt(int(h.handle.Fd()), unix.HIDIOCGRDESCSIZE)
	if err != nil {
		return err
	}
	value := &unix.HIDRawReportDescriptor{Size: uint32(l)}
	err = unix.IoctlHIDGetDesc(int(h.handle.Fd()), value)
	if err != nil {
		return err
	}
	if value.Value[0] != 0x06 || value.Value[1] != 0xd0 || value.Value[2] != 0xf1 {
		return fmt.Errorf("invalid report descriptor or no Fido device")
	}
	//parse report descriptor in a most naive way... but it works... i hope
	if (value.Value[17] != 0x95) || (value.Value[30] != 0x95) {
		return fmt.Errorf("invalid report descriptor, can't find max input/output length")
	}
	report_size_in = uint16(value.Value[18])
	report_size_out = uint16(value.Value[31])
	return nil
}

func (h *HidDevice) GetRawName() (string, error) {
	if h.handle == nil {
		return "", fmt.Errorf("handle is nil")
	}
	name, err := unix.IoctlHIDGetRawName(int(h.handle.Fd()))
	if err != nil {
		return "", err
	}
	return name, nil
}
func (h *HidDevice) GetRawInfo() (*unix.HIDRawDevInfo, error) {
	if h.handle == nil {
		return nil, fmt.Errorf("handle is nil")
	}
	info, err := unix.IoctlHIDGetRawInfo(int(h.handle.Fd()))
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (h *HidDevice) IsFido() (bool, error) {
	if h.handle == nil {
		return false, fmt.Errorf("handle is nil")
	}
	l, err := unix.IoctlGetInt(int(h.handle.Fd()), unix.HIDIOCGRDESCSIZE)
	if err != nil {
		return false, err
	}
	value := &unix.HIDRawReportDescriptor{Size: uint32(l)}
	err = unix.IoctlHIDGetDesc(int(h.handle.Fd()), value)
	if err != nil {
		return false, err
	}
	if value.Value[0] != 0x06 || value.Value[1] != 0xd0 || value.Value[2] != 0xf1 {
		return false, nil
	}
	return true, nil
}
