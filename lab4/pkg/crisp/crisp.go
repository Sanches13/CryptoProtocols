package lab4_crisp

import (
	"crisp/pkg/kdf"
	"crisp/pkg/magma"
	"crisp/pkg/mgm"
	"crisp/pkg/xorshiftplus"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
)

var (
	ExternalKeyIdFlagWithVersion = []byte{ // 1 bit + 15 bits
		0x00, 0x00,
	}
	CS = []byte{ // 8 bits
		0xfa,
	}
	KeyId = []byte{ // 8 bits
		0x80,
	}
)

const (
	BlockSize  = 8  // bytes
	KeySize    = 32 // bytes
	PacketSize = 48 // byte
)

type Crisp struct {
	Decoder    Decoder
	Encoder    Encoder
	randomSeed [16]byte
}

func (c *Crisp) Close() {
	for i := 0; i < len(c.randomSeed); i++ {
		c.randomSeed[i] = 0x00
	}
	c.Decoder.kdf.Close()
	// c.Decoder.cipher.Close()
	c.Decoder.seqNum = 0
	c.Encoder.kdf.Close()
	// c.Encoder.cipher.Close()
	c.Encoder.seqNum = 0
	runtime.GC()
	fmt.Printf("Clear mem [Crisp]: %p\n", &c)
}

type Decoder struct {
	random *xorshiftplus.XorShift128Plus
	kdf    *kdf.KDF
	seqNum uint32
}

type Encoder struct {
	random *xorshiftplus.XorShift128Plus
	kdf    *kdf.KDF
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

func New(key []byte, randomSeed [16]byte) *Crisp {
	if len(key) != KeySize {
		panic("Key size should be 32 bytes")
	}

	kdf := kdf.NewKDF(key[:])
	return &Crisp{
		Decoder: Decoder{
			random: xorshiftplus.New(randomSeed),
			kdf:    kdf,
			seqNum: 0,
		},
		Encoder: Encoder{
			random: xorshiftplus.New(randomSeed),
			kdf:    kdf,
			seqNum: 0,
		},
		randomSeed: randomSeed,
	}
}

func (c *Crisp) Reset() {
	c.Encoder.seqNum = 0
	c.Encoder.random = xorshiftplus.New(c.randomSeed)
	c.Decoder.seqNum = 0
	c.Decoder.random = xorshiftplus.New(c.randomSeed)
}

func (c *Crisp) Encode(plainText []byte) []Message {
	var res []Message

	c.Reset()
	for i := 0; i < len(plainText); i += BlockSize {
		message := c.EncodeNextBlock(plainText[i : i+BlockSize])
		res = append(res, message)
	}

	return res
}

func (c *Crisp) EncodeNextBlock(plainText []byte) Message {
	if len(plainText) != BlockSize {
		panic("Block size should be 16 bytes")
	}
	e := c.Encoder

	var seqNum [4]byte
	var seed [8]byte
	binary.BigEndian.PutUint32(seqNum[:], e.seqNum)
	binary.BigEndian.PutUint64(seed[:], e.random.Next())

	// Key(N)
	key := e.kdf.Derive(seqNum[:], seed[:], 1)

	// text[N]
	block := plainText[:]

	// Payload(N), Mac(N)
	nonce := make([]byte, magma.BlockSize)
	additionalData := []byte{}
	b := magma.NewCipher(key)
	aead, _ := mgm.NewMGM(b, magma.BlockSize)
	ciphertext := aead.Seal(nil, nonce, block, additionalData)
	mac := mgm.CreateVerificationCode(ciphertext, key)

	var message []byte
	message = append(message, ExternalKeyIdFlagWithVersion...)
	message = append(message, CS...)
	message = append(message, KeyId...)
	message = append(message, seqNum[:]...)
	message = append(message, ciphertext[:]...)
	message = append(message, mac...)

	e.seqNum += 1 // complete current iteration and prepare next
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
		decoded := c.DecodeNextBlock(b)
		res = append(res, decoded)
	}

	return res
}

func (c *Crisp) DecodeNextBlock(cipherText []byte) []byte {
	if len(cipherText) != PacketSize {
		panic("Block size should be equal 56 bytes")
	}
	d := c.Decoder

	var seqNum [4]byte
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], d.random.Next())

	// parse
	seqNum = [4]byte(cipherText[4:8])
	payload := cipherText[8:24]
	// mac := cipherText[24:56]

	nonce := make([]byte, magma.BlockSize)
	additionalData := []byte{}
	key := d.kdf.Derive(seqNum[:], seed[:], 1)
	block := magma.NewCipher(key)
	aead, _ := mgm.NewMGM(block, magma.BlockSize)
	decrypt, _ := aead.Open(nil, nonce, payload, additionalData)

	return decrypt[:]
}

func (m *Message) String() string {
	format :=
		`Message:
    ExternalKeyIdFlagWithVersion: %s
    CS:                           %s
    KeyId:                        %s
    SeqNum:                       %s
    Payload:                      %s
    ICV:                          %s
    As block:                     %s`

	return fmt.Sprintf(format,
		hex.EncodeToString(m.ExternalKeyIdFlagWithVersion),
		hex.EncodeToString(m.CS),
		hex.EncodeToString(m.KeyId),
		hex.EncodeToString(m.SeqNum),
		hex.EncodeToString(m.Payload),
		hex.EncodeToString(m.ICV),
		hex.EncodeToString(m.Digits))
}
