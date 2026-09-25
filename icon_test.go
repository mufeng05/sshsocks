package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func iconImage(size int, bg rgb) *image.NRGBA {
	px := renderIcon(size, bg)
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for i := 0; i < len(px); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = px[i+2], px[i+1], px[i], px[i+3]
	}
	return img
}

func TestRenderIcon(t *testing.T) {
	px := renderIcon(32, colorOK)
	corner, center := px[3], px[(16*32+16)*4+3]
	if corner != 0 || center != 255 {
		t.Errorf("角落应透明、中心应不透明：%d %d", corner, center)
	}
}

// 设置 SSHSOCKS_ICON_OUT=目录 时生成预览图和程序图标 icon.ico：
//
//	$env:SSHSOCKS_ICON_OUT="winres"; go test -run TestWriteIcons .
func TestWriteIcons(t *testing.T) {
	dir := os.Getenv("SSHSOCKS_ICON_OUT")
	if dir == "" {
		t.Skip("未设置 SSHSOCKS_ICON_OUT")
	}
	os.MkdirAll(dir, 0o755)

	// 预览：四种状态色 × 常见托盘尺寸，放大 8 倍便于查看
	sizes := []int{16, 20, 24, 32}
	colors := []rgb{colorOK, colorBusy, colorError, colorIdle}
	const zoom = 8
	sheet := image.NewNRGBA(image.Rect(0, 0, (16+20+24+32+4*4)*zoom, 4*36*zoom))
	for row, c := range colors {
		x0 := 0
		for _, s := range sizes {
			img := iconImage(s, c)
			for y := range s * zoom {
				for x := range s * zoom {
					sheet.Set(x0+x, row*36*zoom+y, img.At(x/zoom, y/zoom))
				}
			}
			x0 += (s + 4) * zoom
		}
	}
	writePNG(t, filepath.Join(dir, "preview.png"), sheet)

	// 多尺寸 ICO，每个尺寸单独渲染，小图标也清晰
	var images [][]byte
	icoSizes := []int{16, 20, 24, 32, 40, 48, 64, 128, 256}
	for _, s := range icoSizes {
		var buf bytes.Buffer
		png.Encode(&buf, iconImage(s, colorApp))
		images = append(images, buf.Bytes())
	}
	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, [3]uint16{0, 1, uint16(len(icoSizes))})
	offset := 6 + 16*len(icoSizes)
	for i, s := range icoSizes {
		dim := byte(s)
		if s == 256 {
			dim = 0
		}
		ico.Write([]byte{dim, dim, 0, 0})
		binary.Write(&ico, binary.LittleEndian, []uint16{1, 32})
		binary.Write(&ico, binary.LittleEndian, []uint32{uint32(len(images[i])), uint32(offset)})
		offset += len(images[i])
	}
	for _, b := range images {
		ico.Write(b)
	}
	if err := os.WriteFile(filepath.Join(dir, "icon.ico"), ico.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writePNG(t *testing.T, path string, img image.Image) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}
