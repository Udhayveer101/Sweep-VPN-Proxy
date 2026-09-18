package main

import (
	"bytes"
	"encoding/binary"
)

// icon draws a 32x32 filled circle as an .ico (what the tray wants on Windows),
// so the app ships no image files.
func icon(r, g, b byte) []byte {
	const n = 32
	pixels := make([]byte, 0, n*n*4)
	for y := n - 1; y >= 0; y-- { // BMP rows run bottom-up
		for x := 0; x < n; x++ {
			dx, dy := float64(x)-15.5, float64(y)-15.5
			alpha := byte(0)
			if d := dx*dx + dy*dy; d <= 14*14 {
				alpha = 255
			} else if d <= 15*15 {
				alpha = 128
			}
			pixels = append(pixels, b, g, r, alpha)
		}
	}
	mask := make([]byte, ((n+31)/32*4)*n)
	var img bytes.Buffer
	binary.Write(&img, binary.LittleEndian, []uint32{40, n, n * 2})
	binary.Write(&img, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&img, binary.LittleEndian, []uint32{0, uint32(len(pixels) + len(mask)), 0, 0, 0, 0})
	img.Write(pixels)
	img.Write(mask)

	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, []uint16{0, 1, 1})
	out.Write([]byte{n, n, 0, 0})
	binary.Write(&out, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&out, binary.LittleEndian, []uint32{uint32(img.Len()), 22})
	out.Write(img.Bytes())
	return out.Bytes()
}
