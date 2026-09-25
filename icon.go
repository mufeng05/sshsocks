package main

import "math"

type rgb struct{ r, g, b uint8 }

// 托盘图标的颜色表示整体状态。
var (
	colorOK    = rgb{0x16, 0xa3, 0x4a} // 全部已连接
	colorBusy  = rgb{0xd9, 0x77, 0x06} // 有代理正在连接
	colorError = rgb{0xdc, 0x26, 0x26} // 有代理连接失败
	colorIdle  = rgb{0x6b, 0x72, 0x80} // 没有配置代理
	colorApp   = rgb{0x25, 0x63, 0xeb} // 程序图标
)

// renderIcon 画一个 size×size 的图标：圆形底色上一对白色链环。
// 返回自上而下、每像素 BGRA 四字节的数据（alpha 未预乘）。
func renderIcon(size int, bg rgb) []byte {
	const ss = 4 // 每个像素 4×4 次采样做抗锯齿
	px := make([]byte, size*size*4)
	for y := range size {
		for x := range size {
			disc, glyph := 0, 0
			for sy := range ss {
				for sx := range ss {
					u := (float64(x) + (float64(sx)+0.5)/ss) / float64(size)
					v := (float64(y) + (float64(sy)+0.5)/ss) / float64(size)
					if math.Hypot(u-0.5, v-0.5) > 0.5 {
						continue
					}
					disc++
					if inChainGlyph(u-0.5, v-0.5) {
						glyph++
					}
				}
			}
			if disc == 0 {
				continue
			}
			mix := func(c uint8) byte { return byte((int(c)*(disc-glyph) + 255*glyph) / disc) }
			i := (y*size + x) * 4
			px[i], px[i+1], px[i+2] = mix(bg.b), mix(bg.g), mix(bg.r)
			px[i+3] = byte(255 * disc / (ss * ss))
		}
	}
	return px
}

// inChainGlyph 判断以圆心为原点的点 (x, y) 是否落在两个斜放、相扣的链环上。
func inChainGlyph(x, y float64) bool {
	// 旋转 45°，让链环沿左下到右上的对角线排列
	u := (x - y) / math.Sqrt2
	v := (x + y) / math.Sqrt2
	const (
		half   = 0.085 // 链环直线段的半长
		radius = 0.10  // 环的中心线半径
		width  = 0.048 // 环的半宽
	)
	// 两个链环沿对角线错开，并在垂直方向稍微错位，免得看起来连成一整条
	for _, c := range [][2]float64{{-0.14, 0.035}, {0.14, -0.035}} {
		du := math.Max(math.Abs(u-c[0])-half, 0) // 到链环中线段的距离
		if d := math.Hypot(du, v-c[1]); math.Abs(d-radius) <= width {
			return true
		}
	}
	return false
}
