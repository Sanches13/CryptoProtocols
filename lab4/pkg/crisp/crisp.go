package crisp

import (
	"crisp/pkg/kdf"
	"crisp/pkg/magma"
	"crisp/pkg/mgm"
	"crisp/pkg/xorshiftplus"
	"encoding/binary"
	"fmt"
	"log"
	"runtime"
)

var (
	ExternalKeyIdFlagWithVersion = []byte{
		0x00, 0x00,
	}
	CS = []byte{
		0xf5,
	}
	KeyId = []byte{
		0x80,
	}
)

const (
	BlockSize  = 8
	KeySize    = 32
	PacketSize = 40
)

type Crisp struct {
	Decoder Decoder
	Encoder Encoder
	Seed    [16]byte
}

func (c *Crisp) Close() {
	for i := 0; i < len(c.Seed); i++ {
		c.Seed[i] = 0x00
	}
	c.Decoder.kdf.Close()
	c.Decoder.seqNum = 0
	c.Encoder.kdf.Close()
	c.Encoder.seqNum = 0
	runtime.GC()
	log.Println("Очищена память, хранящая ключевую информацию в структуре KDF")
}

type Decoder struct {
	random *xorshiftplus.XorShift128Plus
	kdf    *kdf.KDF
	cipher *mgm.MGM
	seqNum uint32
}

type Encoder struct {
	random *xorshiftplus.XorShift128Plus
	kdf    *kdf.KDF
	cipher *mgm.MGM
	seqNum uint32
}

type Message struct {
	ExternalKeyIdFlagWithVersion []byte
	CS                           []byte
	KeyId                        []byte
	SeqNum                       []byte
	Payload                      []byte
	ICV                          []byte
	Digits                       []byte
}

func New(key []byte, Seed [16]byte) *Crisp {
	if len(key) != KeySize {
		panic("Key size should be 32 bytes")
	}

	label := []byte{
		0x26, 0xbd, 0xb8, 0x78,
	}
	seed := []byte{
		0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78,
	}
	kdf := kdf.NewKDF(key[:])
	new_key := kdf.Diversify(label, seed, 1)
	block := magma.NewCipher(new_key)
	cipher, _ := mgm.NewMGM(block, magma.BlockSize)
	return &Crisp{
		Decoder: Decoder{
			random: xorshiftplus.New(Seed),
			kdf:    kdf,
			cipher: cipher,
			seqNum: 0,
		},
		Encoder: Encoder{
			random: xorshiftplus.New(Seed),
			kdf:    kdf,
			cipher: cipher,
			seqNum: 0,
		},
		Seed: Seed,
	}
}

func (c *Crisp) Reset() {
	c.Encoder.seqNum = 0
	c.Encoder.random = xorshiftplus.New(c.Seed)
	c.Decoder.seqNum = 0
	c.Decoder.random = xorshiftplus.New(c.Seed)
}

func (c *Crisp) Encode(plainText []byte) []Message {
	var res []Message

	c.Reset()
	for i := 0; i < len(plainText); i += BlockSize {
		message := c.EncodeBlock(plainText[i : i+BlockSize])
		res = append(res, message)
	}

	return res
}

func (c *Crisp) EncodeBlock(plainText []byte) Message {
	if len(plainText) != BlockSize {
		panic("Block size should be 16 bytes")
	}
	e := c.Encoder

	var seqNum [4]byte
	var seed [8]byte
	binary.BigEndian.PutUint32(seqNum[:], e.seqNum)
	binary.BigEndian.PutUint64(seed[:], e.random.Next())

	block := plainText[:]

	nonce := make([]byte, magma.BlockSize)
	additionalData := []byte{}
	ciphertext, mac := e.cipher.Seal(nil, nonce, block, additionalData)

	var message []byte
	message = append(message, ExternalKeyIdFlagWithVersion...)
	message = append(message, CS...)
	message = append(message, KeyId...)
	message = append(message, seqNum[:]...)
	message = append(message, ciphertext[:]...)
	message = append(message, mac...)

	e.seqNum += 1
	return Message{
		ExternalKeyIdFlagWithVersion: ExternalKeyIdFlagWithVersion,
		CS:                           CS,
		KeyId:                        KeyId,
		SeqNum:                       seqNum[:],
		Payload:                      ciphertext[:],
		ICV:                          mac[:],
		Digits:                       message,
	}
}

func (c *Crisp) Decode(cipherText [][]byte) [][]byte {
	for i, b := range cipherText {
		if len(b) != PacketSize {
			panic(fmt.Sprintf("Block size of block [%d] should be 56 bytes", i))
		}
	}

	var res [][]byte
	for _, b := range cipherText {
		decoded := c.DecodeBlock(b)
		res = append(res, decoded)
	}

	return res
}

func (c *Crisp) DecodeBlock(cipherText []byte) []byte {
	if len(cipherText) != PacketSize {
		panic("Block size should be equal 56 bytes")
	}
	d := c.Decoder

	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], d.random.Next())

	// seqNum = [4]byte(cipherText[4:8])
	payload := cipherText[8:24]
	// mac := cipherText[24:56]

	nonce := make([]byte, magma.BlockSize)
	additionalData := []byte{}
	decrypt, _ := d.cipher.Open(nil, nonce, payload, additionalData)

	return decrypt[:]
}
