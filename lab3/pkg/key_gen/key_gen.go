package key_gen

import (
	"encoding/binary"
	"os"
	"xorshiftplus/pkg/xorshiftplus"
)

func CreateFile(rand *xorshiftplus.XorShift128Plus, iters int, filename string) {

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic("failed to create file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	for i := 0; i < iters; i++ {
		var nextBatch [8]byte
		value := rand.Next()
		binary.LittleEndian.PutUint64(nextBatch[:], value)

		_, err := file.Write(nextBatch[:])
		if err != nil {
			panic("failed to append to file: " + err.Error())
		}
	}
}
