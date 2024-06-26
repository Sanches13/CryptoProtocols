package file_integrity

import (
	"fmt"
	"magma_mgm/pkg/streebog"
	"os"
)

func Integrity_check(inputPath string) []byte {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Printf("ошибка при чтении файла %s: %v", inputPath, err)
		return nil
	}

	h256 := streebog.NewHash()
	h256.Write(data)

	return h256.Sum(nil)
}
