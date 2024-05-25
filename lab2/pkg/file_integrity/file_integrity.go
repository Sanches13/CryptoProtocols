package file_integrity

import (
	"kdf_gostr/pkg/streebog"
	"log"
	"os"
)

func Integrity_check(inputPath string) []byte {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		log.Printf("Ошибка при чтении файла %s: %v", inputPath, err)
		return nil
	}

	h256 := streebog.NewHash()
	h256.Write(data)

	return h256.Sum(nil)
}
