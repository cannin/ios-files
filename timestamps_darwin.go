//go:build darwin

package main

import (
	"encoding/binary"
	"time"

	"golang.org/x/sys/unix"
)

// setFileCreationTime sets the macOS filesystem birth time for filename.
func setFileCreationTime(filename string, createdAt time.Time) error {
	timestamp := unix.NsecToTimespec(createdAt.UnixNano())
	attributeList := unix.Attrlist{
		Bitmapcount: unix.ATTR_BIT_MAP_COUNT,
		Commonattr:  unix.ATTR_CMN_CRTIME,
	}
	attributeBuffer := make([]byte, 16)
	binary.NativeEndian.PutUint64(attributeBuffer[0:8], uint64(timestamp.Sec))
	binary.NativeEndian.PutUint64(attributeBuffer[8:16], uint64(timestamp.Nsec))
	return unix.Setattrlist(filename, &attributeList, attributeBuffer, 0)
}
