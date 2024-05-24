package main

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"log"
	"magma_mgm/pkg/file_integrity"
	"magma_mgm/pkg/magma"
	"magma_mgm/pkg/mgm"
	"os"
)

// NewMGM создает новый экземпляр MGM для данного блока шифрования и размера тэга
func NewMGM(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	return mgm.NewMGM(block, tagSize)
}

func main() {
	key := []byte{
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	}

	if len(os.Args) == 5 {
		if os.Args[1] == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" {
			log.Println("Введен правильный пароль")
			file_hash := file_integrity.Integrity_check(os.Args[0])
			log.Println("Вычислен хеш исполняемого файла")
			if os.Args[2] == "-e" {
				err := encryptFile(os.Args[3], os.Args[4], key)
				if err != nil {
					log.Fatalf("Ошибка при шифровании файла: %v", err)
				}
				// log.Println("Шифрование завершено успешно")
			} else if os.Args[2] == "-d" {
				err := decryptFile(os.Args[3], os.Args[4], key)
				if err != nil {
					log.Fatalf("Ошибка при расшифровании файла: %v", err)
				}
				// log.Println("Расшифрование завершено успешно")
			} else {
				log.Fatalf("Выбран некорректный режим работы программы")
			}
			if bytes.Compare(file_hash, file_integrity.Integrity_check(os.Args[0])) != 0 {
				log.Fatalf("Нарушена целостность исполняемого файла")
			} else {
				log.Println("Целостность исполняемого файла нарушена не была")
			}
		} else {
			log.Fatalf("Введен неверный пароль")
		}
	} else if len(os.Args) == 3 {
		if os.Args[1] == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" {
			log.Println("Введен правильный пароль")
			if os.Args[2] == "-t" {
				if test_encrypt(key) {
					log.Println("Шифрование завершено успешно")
				} else {
					log.Fatalf("Некорректная работа алгоритма шифрования")
				}
			} else {
				log.Fatalf("Выбран некорректный режим работы программы")
			}
		} else {
			log.Fatalf("Введен неверный пароль")
		}
	} else {
		log.Fatalf("Указано некорректное число аргументов")
	}
}

func encryptFile(inputPath, outputPath string, key []byte) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка при чтении файла %s: %v", inputPath, err)
	}
	// log.Printf("Прочитано %d байт открытого текста\n", len(plaintext))

	nonce := make([]byte, magma.BlockSize)
	block := magma.NewCipher(key)
	defer block.Clear()
	defer log.Println("Выполнена очистка ключевой информации")
	key = nil

	aead, err := NewMGM(block, magma.BlockSize)
	if err != nil {
		return fmt.Errorf("ошибка при создании AEAD: %v", err)
	}

	additionalData := []byte{}
	sealed := aead.Seal(nil, nonce, plaintext, additionalData)
	plaintext = nil
	nonce = nil
	// log.Printf("Создано %d байт зашифрованного текста\n", len(sealed))

	err = os.WriteFile(outputPath, sealed, 0644)
	sealed = nil
	if err != nil {
		return fmt.Errorf("ошибка при записи файла %s: %v", outputPath, err)
	}
	// log.Printf("Зашифрованный текст записан в файл %s\n", outputPath)

	return nil
}

func decryptFile(inputPath, outputPath string, key []byte) error {
	sealed, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("ошибка при чтении файла %s: %v", inputPath, err)
	}
	// log.Printf("Прочитано %d байт зашифрованного текста\n", len(sealed))

	nonce := make([]byte, magma.BlockSize)
	block := magma.NewCipher(key)
	defer block.Clear()
	defer log.Println("Выполнена очистка ключевой информации")
	key = nil

	aead, err := NewMGM(block, magma.BlockSize)
	if err != nil {
		return fmt.Errorf("ошибка при создании AEAD: %v", err)
	}

	additionalData := []byte{}
	plaintext, err := aead.Open(nil, nonce, sealed, additionalData)
	sealed = nil
	nonce = nil
	if err != nil {
		return fmt.Errorf("ошибка при расшифровании: %v", err)
	}
	// fmt.Printf("Создано %d байт расшифрованного текста\n", len(plaintext))

	err = os.WriteFile(outputPath, plaintext, 0644)
	plaintext = nil
	if err != nil {
		return fmt.Errorf("ошибка при записи файла %s: %v", outputPath, err)
	}
	// fmt.Printf("Расшифрованный текст записан в файл %s\n", outputPath)

	return nil
}

func test_encrypt(key []byte) bool {
	var test_plaintext []byte = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}

	nonce := make([]byte, magma.BlockSize)
	block := magma.NewCipher(key)
	defer block.Clear()
	defer log.Println("Выполнена очистка ключевой информации")
	key = nil

	aead, err := NewMGM(block, magma.BlockSize)
	if err != nil {
		// fmt.Println("ошибка при создании AEAD: %v", err)
		return false
	}

	additionalData := []byte{}
	sealed := aead.Seal(nil, nonce, test_plaintext, additionalData)
	test_plaintext = nil
	nonce = nil
	// fmt.Printf("Создано %d байт зашифрованного текста\n", len(sealed))

	var test_sealed []byte = []byte{0xc3, 0xce, 0xa9, 0xb4, 0x08, 0xce, 0x59, 0x76,
		0xa8, 0x75, 0x36, 0x8f, 0x86, 0x65, 0x0a, 0x39,
		0x03, 0x4d, 0x13, 0xc2, 0x44, 0x7a, 0x2a, 0x3f}
	if bytes.Compare(test_sealed, sealed) != 0 {
		return false
	}

	return true
}
