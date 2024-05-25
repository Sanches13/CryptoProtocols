package key_gen

import (
	"encoding/binary"
	"kdf_gostr/pkg/kdf"
	"log"
	"os"
)

func CreateFile(key []byte, iters int, filename string) {
	kdf := kdf.NewKDF(key)
	defer kdf.Close()

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Println("failed to create file: " + err.Error())
		panic("failed to create file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	label := []byte{
		0x00, 0x01, 0x02, 0x03,
	}
	for i := 0; i < iters; i++ {
		var seq [8]byte
		binary.LittleEndian.PutUint64(seq[:], uint64(i))

		nextKey := kdf.Derive(label, seq[:], 1)

		_, err := file.Write(nextKey[:])
		if err != nil {
			log.Println("failed to append to file: " + err.Error())
			panic("failed to append to file: " + err.Error())
		}
	}
}
