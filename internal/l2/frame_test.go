package l2

import (
	"bytes"
	"testing"
)

func TestWriteReadPacketRoundTrip(t *testing.T) {
	cases := [][]byte{
		bytes.Repeat([]byte{0xAB}, 1),
		bytes.Repeat([]byte{0xCD}, 64),
		bytes.Repeat([]byte{0xEF}, 1448),
		bytes.Repeat([]byte{0x12}, MaxEtherFrame),
	}
	var buf bytes.Buffer
	for _, frame := range cases {
		buf.Reset()
		if err := WritePacket(&buf, frame); err != nil {
			t.Fatalf("WritePacket(%d): %v", len(frame), err)
		}
		out := make([]byte, MaxEtherFrame)
		n, err := ReadPacket(&buf, out)
		if err != nil {
			t.Fatalf("ReadPacket(%d): %v", len(frame), err)
		}
		if !bytes.Equal(out[:n], frame) {
			t.Fatalf("round trip mismatch for len %d", len(frame))
		}
	}
}

func TestWritePacketRejectsBadLength(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePacket(&buf, nil); err == nil {
		t.Fatal("expected error for empty frame")
	}
	if err := WritePacket(&buf, make([]byte, MaxEtherFrame+1)); err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestReadPacketBufferTooSmall(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePacket(&buf, bytes.Repeat([]byte{1}, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPacket(&buf, make([]byte, 50)); err == nil {
		t.Fatal("expected error for undersized buffer")
	}
}
