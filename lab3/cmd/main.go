package main

import (
	"xorshiftplus/pkg/key_gen"
	"xorshiftplus/pkg/xorshiftplus"
)

func main() {
	var seed [16]byte

	generator := xorshiftplus.New(seed)
	generator.NextState()
	key_gen.CreateFile(generator, 131072000, "gen_file")
	// 13107200
	// 131072000
	// 1000
	// 100000
}
