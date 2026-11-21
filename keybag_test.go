package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAESKeyUnwrapRFC3394(t *testing.T) {
	t.Parallel()

	keyEncryptionKey := mustDecodeHex(t, "000102030405060708090A0B0C0D0E0F")
	wrapped := mustDecodeHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	want := mustDecodeHex(t, "00112233445566778899AABBCCDDEEFF")

	got, err := aesKeyUnwrap(keyEncryptionKey, wrapped)
	if err != nil {
		t.Fatalf("aesKeyUnwrap() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("aesKeyUnwrap() = %X, want %X", got, want)
	}
}

func TestAESKeyUnwrapRejectsModifiedCiphertext(t *testing.T) {
	t.Parallel()

	keyEncryptionKey := mustDecodeHex(t, "000102030405060708090A0B0C0D0E0F")
	wrapped := mustDecodeHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	wrapped[len(wrapped)-1] ^= 0xff

	if _, err := aesKeyUnwrap(keyEncryptionKey, wrapped); err == nil {
		t.Fatal("aesKeyUnwrap() accepted modified ciphertext")
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	return decoded
}
