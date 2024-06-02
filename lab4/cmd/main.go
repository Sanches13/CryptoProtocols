package main

import (
	"bytes"
	"crisp/pkg/access_control"
	lab4 "crisp/pkg/crisp"
	"crisp/pkg/file_integrity"
	"log"
	"os"
)

const (
	BlockSize  = 8
	KeySize    = 32
	PacketSize = 32
)

func main() {

	if len(os.Args) == 5 {
		if access_control.CheckAccessControl(os.Args[1]) {
			key := []byte{
				0x80, 0x94, 0xA8, 0xBC, 0xC0, 0xD4, 0xE8, 0xFC,
				0x81, 0x95, 0xA9, 0xBD, 0xC1, 0xD5, 0xE9, 0xFD,
				0x82, 0x96, 0xAA, 0xBE, 0xC2, 0xD6, 0xEA, 0xFE,
				0x83, 0x97, 0xAB, 0xBF, 0xC3, 0xD7, 0xEB, 0xFF,
			}
			log.Println("Введен правильный пароль")
			file_hash := file_integrity.Integrity_check(os.Args[0])
			log.Println("Вычислен хеш исполняемого файла")
			if os.Args[2] == "-e" {
				_ = encryptFile(os.Args[3], os.Args[4], key)
			} else if os.Args[2] == "-d" {
				_ = decryptFile(os.Args[3], os.Args[4], key)
			} else {
				log.Fatalf("Выбран некорректный режим работы программы")
			}
			if !bytes.Equal(file_hash, file_integrity.Integrity_check(os.Args[0])) {
				log.Fatalf("Нарушена целостность исполняемого файла")
			} else {
				log.Println("Целостность исполняемого файла нарушена не была")
			}
		} else {
			log.Fatalf("Введен неверный пароль")
		}
	} else if len(os.Args) == 3 {
		if access_control.CheckAccessControl(os.Args[1]) {
			key := []byte{
				0x80, 0x94, 0xA8, 0xBC, 0xC0, 0xD4, 0xE8, 0xFC,
				0x81, 0x95, 0xA9, 0xBD, 0xC1, 0xD5, 0xE9, 0xFD,
				0x82, 0x96, 0xAA, 0xBE, 0xC2, 0xD6, 0xEA, 0xFE,
				0x83, 0x97, 0xAB, 0xBF, 0xC3, 0xD7, 0xEB, 0xFF,
			}
			if test_encrypt(key) {
				log.Println("Корректность работы алгоритма проверена. Успешно")
			} else {
				log.Fatalf("Корректность работы алгоритма проверена. Ошибка")
			}
		} else {
			log.Fatalf("Введен неверный пароль")
		}
	} else {
		log.Fatalf("Указано некорректное число аргументов")
	}
}

func encryptFile(inputPath, outputPath string, key []byte) error {
	var Seed [16]byte
	crisp := lab4.New(key[:], Seed)
	defer crisp.Close()

	b, err := os.ReadFile(inputPath)
	if err != nil {
		panic("failed to open file: " + err.Error())
	}

	file, err := os.Create(outputPath)
	if err != nil {
		log.Println("Unable to create file:", err)
		os.Exit(1)
	}
	defer file.Close()

	for i := 0; i < len(b); i += BlockSize {
		message := crisp.EncodeBlock(b[i : i+BlockSize])
		file.Write(message.Digits)
	}
	return nil
}

func decryptFile(inputPath, outputPath string, key []byte) error {
	var Seed [16]byte
	crisp := lab4.New(key[:], Seed)
	defer crisp.Close()

	b, err := os.ReadFile(inputPath)
	if err != nil {
		panic("failed to open file: " + err.Error())
	}

	file, err := os.Create(outputPath)
	if err != nil {
		log.Println("Unable to create file:", err)
		os.Exit(1)
	}
	defer file.Close()

	for i := 0; i < len(b); i += PacketSize {
		decoded := crisp.DecodeBlock(b[i : i+PacketSize])
		file.Write(decoded)
	}
	return nil
}

func test_encrypt(key []byte) bool {
	var Seed [16]byte
	crisp := lab4.New(key[:], Seed)
	defer crisp.Close()

	message := []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	encrypted_message := []byte{0x00, 0x00, 0xfa, 0x80, 0x00, 0x00, 0x00, 0x00,
		0x6a, 0x18, 0xa7, 0x44, 0xaf, 0xe2, 0x51, 0x80,
		0x0a, 0x8b, 0x54, 0x68, 0xe1, 0x1f, 0x0c, 0x02,
		0xca, 0xc8, 0x4e, 0x67, 0xe4, 0xca, 0x95, 0xc4}

	for i := 0; i < len(message); i += BlockSize {
		encoded := crisp.EncodeBlock(message[i : i+BlockSize])
		if !bytes.Equal(encrypted_message[i:i+PacketSize], encoded.Digits) {
			return false
		}
	}
	return true
}
