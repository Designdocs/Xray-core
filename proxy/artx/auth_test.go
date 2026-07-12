package artx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestAuthFrameGoldenVector(t *testing.T) {
	psk := []byte("artx-wire-v1-test-psk")
	salt := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f")
	exporter := mustDecodeHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	padding := mustDecodeHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	const bucket = uint32(0x01020304)

	locatorMAC := hmac.New(sha256.New, psk)
	_, _ = locatorMAC.Write([]byte("artx-user-locator-v1"))
	wantLocator := locatorMAC.Sum(nil)[:UserLocatorLength]
	if got := hex.EncodeToString(wantLocator); got != "6cc5f96d2384bf26" {
		t.Fatalf("independent locator calculation = %s", got)
	}

	tagMAC := hmac.New(sha256.New, psk)
	_, _ = tagMAC.Write(salt)
	_, _ = tagMAC.Write(exporter)
	var bucketBytes [4]byte
	binary.BigEndian.PutUint32(bucketBytes[:], bucket)
	_, _ = tagMAC.Write(bucketBytes[:])
	wantTag := tagMAC.Sum(nil)
	if got := hex.EncodeToString(wantTag); got != "43935f299974be9ab1a248940eb7e877876ecd7e90fbb78218d03e1e003abcf3" {
		t.Fatalf("independent tag calculation = %s", got)
	}

	frame, err := NewAuthFrame(psk, salt, exporter, bucket, padding)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	const wantFrame = "0110000102030405060708090a0b0c0d0e0f6cc5f96d2384bf260102030443935f299974be9ab1a248940eb7e877876ecd7e90fbb78218d03e1e003abcf30010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	if got := hex.EncodeToString(encoded); got != wantFrame {
		t.Fatalf("auth frame = %s", got)
	}

	decoded, err := ReadAuthFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Verify(psk, exporter) {
		t.Fatal("golden auth frame did not verify")
	}
	otherExporter := append([]byte(nil), exporter...)
	otherExporter[0] ^= 0xff
	if decoded.Verify(psk, otherExporter) {
		t.Fatal("auth frame verified against a different TLS exporter")
	}
}

func TestAuthFrameSaltBoundaries(t *testing.T) {
	psk := []byte("psk")
	exporter := make([]byte, ExporterLength)

	for _, size := range []int{MinSaltLength, MaxSaltLength} {
		if _, err := NewAuthFrame(psk, make([]byte, size), exporter, 1, nil); err != nil {
			t.Fatalf("salt length %d rejected: %v", size, err)
		}
	}
	for _, size := range []int{MinSaltLength - 1, MaxSaltLength + 1} {
		if _, err := NewAuthFrame(psk, make([]byte, size), exporter, 1, nil); err == nil {
			t.Fatalf("salt length %d accepted", size)
		}
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
