package main

import (
	"flag"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
)

func main() {
	size := flag.Int("size", 64, "icon size")
	out := flag.String("out", "PACKAGE_ICON.PNG", "output path")
	flag.Parse()
	img := image.NewRGBA(image.Rect(0, 0, *size, *size))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{R: 12, G: 19, B: 21, A: 255}}, image.Point{}, draw.Src)
	line := color.RGBA{R: 184, G: 243, B: 74, A: 255}
	muted := color.RGBA{R: 52, G: 74, B: 77, A: 255}
	margin := *size / 7
	for x := margin; x < *size-margin; x++ {
		for y := margin; y < *size-margin; y++ {
			if x == margin || x == *size-margin-1 || y == margin || y == *size-margin-1 {
				img.Set(x, y, muted)
			}
		}
	}
	barWidth := max(2, *size/10)
	gap := max(2, *size/16)
	heights := []int{*size / 4, *size / 2, *size * 3 / 8}
	startX := *size/2 - (3*barWidth+2*gap)/2
	baseY := *size - 2*margin
	for i, height := range heights {
		x0 := startX + i*(barWidth+gap)
		for x := x0; x < x0+barWidth; x++ {
			for y := baseY - height; y < baseY; y++ {
				img.Set(x, y, line)
			}
		}
	}
	file, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if err := png.Encode(file, img); err != nil {
		panic(err)
	}
}
