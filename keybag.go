package main

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// wrapPassphrase marks class keys protected by the backup passphrase.
const wrapPassphrase = uint32(2)

// A classKey contains the wrapping state and key material for a protection class.
type classKey struct {
	class      uint32
	wrap       uint32
	wrappedKey []byte
	key        []byte
}

// A keybag contains backup attributes and keys grouped by protection class.
type keybag struct {
	attributes map[string]any
	classKeys  map[uint32]*classKey
}

// parseKeybag returns the backup keybag represented by Apple's tag-length-value
// data.
func parseKeybag(data []byte) (*keybag, error) {
	bag := &keybag{
		attributes: make(map[string]any),
		classKeys:  make(map[uint32]*classKey),
	}
	var current *classKey
	seenBagUUID := false

	for offset := 0; offset < len(data); {
		if len(data)-offset < 8 {
			return nil, errors.New("truncated keybag tag header")
		}
		tag := string(data[offset : offset+4])
		length := int(binary.BigEndian.Uint32(data[offset+4 : offset+8]))
		offset += 8
		if length < 0 || length > len(data)-offset {
			return nil, fmt.Errorf("invalid keybag length for tag %q", tag)
		}
		value := append([]byte(nil), data[offset:offset+length]...)
		offset += length

		if tag == "UUID" {
			if !seenBagUUID {
				seenBagUUID = true
				bag.attributes[tag] = value
				continue
			}
			if current != nil {
				if current.class == 0 {
					return nil, errors.New("keybag class key has no class")
				}
				bag.classKeys[current.class] = current
			}
			current = &classKey{}
			continue
		}

		if current != nil {
			switch tag {
			case "CLAS":
				current.class = decodeUint32(tag, value)
				continue
			case "WRAP":
				current.wrap = decodeUint32(tag, value)
				continue
			case "WPKY":
				current.wrappedKey = value
				continue
			case "KTYP", "PBKY":
				continue
			}
		}

		if len(value) == 4 {
			bag.attributes[tag] = binary.BigEndian.Uint32(value)
		} else {
			bag.attributes[tag] = value
		}
	}

	if current != nil {
		if current.class == 0 {
			return nil, errors.New("keybag class key has no class")
		}
		bag.classKeys[current.class] = current
	}
	if len(bag.classKeys) == 0 {
		return nil, errors.New("keybag contains no class keys")
	}
	return bag, nil
}

// unlock makes the passphrase-protected class keys in bag available using
// password.
func (bag *keybag) unlock(password []byte) error {
	dpsl, err := bag.bytesAttribute("DPSL")
	if err != nil {
		return err
	}
	dpic, err := bag.uint32Attribute("DPIC")
	if err != nil {
		return err
	}
	salt, err := bag.bytesAttribute("SALT")
	if err != nil {
		return err
	}
	iterations, err := bag.uint32Attribute("ITER")
	if err != nil {
		return err
	}
	if dpic == 0 || iterations == 0 {
		return errors.New("keybag contains zero PBKDF2 iterations")
	}

	firstKey := deriveKey(password, dpsl, int(dpic), 32, sha256.New)
	defer clear(firstKey)
	passphraseKey := deriveKey(firstKey, salt, int(iterations), 32, sha1.New)
	defer clear(passphraseKey)

	unlocked := 0
	for _, item := range bag.classKeys {
		if len(item.wrappedKey) == 0 || item.wrap&wrapPassphrase == 0 {
			continue
		}
		item.key, err = aesKeyUnwrap(passphraseKey, item.wrappedKey)
		if err != nil {
			return errors.New("failed to unlock keybag: incorrect password or unsupported backup")
		}
		unlocked++
	}
	if unlocked == 0 {
		return errors.New("keybag contains no passphrase-wrapped class keys")
	}
	return nil
}

// unwrapKeyForClass returns the unwrapped manifest or file key protected by the
// specified class key.
func (bag *keybag) unwrapKeyForClass(class uint32, wrapped []byte) ([]byte, error) {
	item, ok := bag.classKeys[class]
	if !ok {
		return nil, fmt.Errorf("protection class %d is absent from keybag", class)
	}
	if len(item.key) == 0 {
		return nil, fmt.Errorf("protection class %d is locked", class)
	}
	if len(wrapped) != 40 {
		return nil, fmt.Errorf("invalid wrapped key length %d", len(wrapped))
	}
	key, err := aesKeyUnwrap(item.key, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap protection-class key: %w", err)
	}
	return key, nil
}

// close clears unwrapped key material retained by bag.
func (bag *keybag) close() {
	for _, item := range bag.classKeys {
		clear(item.key)
		item.key = nil
	}
}

// aesKeyUnwrap returns the plaintext key from an RFC 3394 wrapped key. It returns
// an error when the wrapped key fails its integrity check.
func aesKeyUnwrap(keyEncryptionKey, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, errors.New("wrapped key must be at least 24 bytes and divisible by 8")
	}
	block, err := aes.NewCipher(keyEncryptionKey)
	if err != nil {
		return nil, err
	}

	n := len(wrapped)/8 - 1
	a := binary.BigEndian.Uint64(wrapped[:8])
	r := make([]byte, n*8)
	copy(r, wrapped[8:])
	buffer := make([]byte, aes.BlockSize)

	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(buffer[:8], a^t)
			copy(buffer[8:], r[(i-1)*8:i*8])
			block.Decrypt(buffer, buffer)
			a = binary.BigEndian.Uint64(buffer[:8])
			copy(r[(i-1)*8:i*8], buffer[8:])
		}
	}

	if a != 0xa6a6a6a6a6a6a6a6 {
		clear(r)
		return nil, errors.New("AES key-unwrapping integrity check failed")
	}
	return r, nil
}

// deriveKey returns a key of length bytes derived from password and salt using
// PBKDF2 with the requested iteration count and hash function.
func deriveKey(password, salt []byte, iterations, length int, hashFunction func() hash.Hash) []byte {
	return pbkdf2.Key(password, salt, iterations, length, hashFunction)
}

// decodeUint32 returns the big-endian uint32 represented by value. It returns
// zero when value is not exactly four bytes long.
func decodeUint32(_ string, value []byte) uint32 {
	if len(value) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(value)
}

// bytesAttribute returns the non-empty byte-valued attribute identified by name.
func (bag *keybag) bytesAttribute(name string) ([]byte, error) {
	value, ok := bag.attributes[name].([]byte)
	if !ok || len(value) == 0 {
		return nil, fmt.Errorf("keybag attribute %s is absent", name)
	}
	return value, nil
}

// uint32Attribute returns the uint32-valued attribute identified by name.
func (bag *keybag) uint32Attribute(name string) (uint32, error) {
	value, ok := bag.attributes[name].(uint32)
	if !ok {
		return 0, fmt.Errorf("keybag attribute %s is absent", name)
	}
	return value, nil
}
