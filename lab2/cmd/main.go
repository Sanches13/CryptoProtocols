package main

import (
	"bytes"
	"kdf_gostr/pkg/access_control"
	"kdf_gostr/pkg/file_integrity"
	"kdf_gostr/pkg/kdf"
	"kdf_gostr/pkg/key_gen"
	"log"
	"os"
)

func main() {
	if len(os.Args) == 4 {
		if access_control.CheckAccessControl(os.Args[1]) {
			log.Println("Введен правильный пароль")
			file_hash := file_integrity.Integrity_check(os.Args[0])
			log.Println("Вычислен хеш исполняемого файла")

			key, err := os.ReadFile(os.Args[2])
			if err != nil {
				log.Fatalf("Ошибка при чтении файла %s: %v", os.Args[2], err)
			}

			iters := 1000000
			key_gen.CreateFile(key, iters, os.Args[3])

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
			log.Println("Введен правильный пароль")
			if os.Args[2] == "-t" {
				file_hash := file_integrity.Integrity_check(os.Args[0])
				log.Println("Вычислен хеш исполняемого файла")
				key := []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				}
				label := []byte{
					0x26, 0xbd, 0xb8, 0x78,
				}
				seed := []byte{
					0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78,
				}
				kdf := kdf.NewKDF(key)
				defer kdf.Close()

				res := kdf.Derive(label, seed, 1)

				if !bytes.Equal(res, []byte{0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3,
					0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
					0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f,
					0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9}) {
					log.Fatalf("Работоспосбность криптографических алгоритмов проверена. Ошибка")
				} else {
					log.Println("Работоспосбность криптографических алгоритмов проверена. Успешно")
				}
				if !bytes.Equal(file_hash, file_integrity.Integrity_check(os.Args[0])) {
					log.Fatalf("Нарушена целостность исполняемого файла")
				} else {
					log.Println("Целостность исполняемого файла нарушена не была")
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
