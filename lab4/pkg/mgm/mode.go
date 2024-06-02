package mgm

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

var (
	R64  *big.Int = big.NewInt(0)
	R128 *big.Int = big.NewInt(0)
)

func init() {
	R64.SetBytes([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b,
	})
	R128.SetBytes([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
	})
}

type MGM struct {
	maxSize   uint64
	cipher    cipher.Block
	blockSize int
	tagSize   int
	icn       []byte
	bufP      []byte
	bufC      []byte
	padded    []byte
	sum       []byte

	x      *big.Int
	y      *big.Int
	z      *big.Int
	maxBit int
	r      *big.Int
	mulBuf []byte
}

func NewMGM(cipher cipher.Block, tagSize int) (*MGM, error) {
	blockSize := cipher.BlockSize()
	// if !(blockSize == 8 || blockSize == 16) {
	// 	return nil, errors.New("MGM supports only 64/128 blocksizes")
	// }
	// if tagSize < 4 || tagSize > blockSize {
	// 	return nil, errors.New("invalid tag size")
	// }
	mgm := MGM{
		maxSize:   uint64(1<<uint(blockSize*8/2) - 1),
		cipher:    cipher,
		blockSize: blockSize,
		tagSize:   tagSize,
		icn:       make([]byte, blockSize),
		bufP:      make([]byte, blockSize),
		bufC:      make([]byte, blockSize),
		padded:    make([]byte, blockSize),
		sum:       make([]byte, blockSize),
		x:         big.NewInt(0),
		y:         big.NewInt(0),
		z:         big.NewInt(0),
		mulBuf:    make([]byte, blockSize),
	}
	if blockSize == 8 {
		mgm.maxBit = 64 - 1
		mgm.r = R64
	} else {
		mgm.maxBit = 128 - 1
		mgm.r = R128
	}
	return &mgm, nil
}

func (mgm *MGM) NonceSize() int {
	return mgm.blockSize
}

func (mgm *MGM) Overhead() int {
	return mgm.tagSize
}

func incr(data []byte) {
	for i := len(data) - 1; i >= 0; i-- {
		data[i]++
		if data[i] != 0 {
			return
		}
	}
}

func xor(dst, src1, src2 []byte) {
	for i := 0; i < len(src1); i++ {
		dst[i] = src1[i] ^ src2[i]
	}
}

func (mgm *MGM) validateNonce(nonce []byte) {
	if len(nonce) != mgm.blockSize {
		panic("nonce length must be equal to cipher's blocksize")
	}
	if nonce[0]&0x80 > 0 {
		panic("nonce must not have higher bit set")
	}
}

func (mgm *MGM) validateSizes(text, additionalData []byte) {
	if len(text) == 0 && len(additionalData) == 0 {
		panic("at least either *text or additionalData must be provided")
	}
	if uint64(len(additionalData)) > mgm.maxSize {
		panic("additionalData is too big")
	}
	if uint64(len(text)+len(additionalData)) > mgm.maxSize {
		panic("*text with additionalData are too big")
	}
}

func (mgm *MGM) auth(out, text, ad []byte) {
	for i := 0; i < mgm.blockSize; i++ {
		mgm.sum[i] = 0
	}
	adLen := len(ad) * 8
	textLen := len(text) * 8
	mgm.icn[0] |= 0x80
	mgm.cipher.Encrypt(mgm.bufP, mgm.icn)
	for len(ad) >= mgm.blockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(
			mgm.sum,
			mgm.sum,
			mgm.mul(mgm.bufC, ad[:mgm.blockSize]),
		)
		incr(mgm.bufP[:mgm.blockSize/2])
		ad = ad[mgm.blockSize:]
	}
	if len(ad) > 0 {
		copy(mgm.padded, ad)
		for i := len(ad); i < mgm.blockSize; i++ {
			mgm.padded[i] = 0
		}
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(mgm.sum, mgm.sum, mgm.mul(mgm.bufC, mgm.padded))
		incr(mgm.bufP[:mgm.blockSize/2])
	}

	for len(text) >= mgm.blockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(
			mgm.sum,
			mgm.sum,
			mgm.mul(mgm.bufC, text[:mgm.blockSize]),
		)
		incr(mgm.bufP[:mgm.blockSize/2])
		text = text[mgm.blockSize:]
	}
	if len(text) > 0 {
		copy(mgm.padded, text)
		for i := len(text); i < mgm.blockSize; i++ {
			mgm.padded[i] = 0
		}
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(mgm.sum, mgm.sum, mgm.mul(mgm.bufC, mgm.padded))
		incr(mgm.bufP[:mgm.blockSize/2])
	}

	mgm.cipher.Encrypt(mgm.bufP, mgm.bufP)
	if mgm.blockSize == 8 {
		binary.BigEndian.PutUint32(mgm.bufC, uint32(adLen))
		binary.BigEndian.PutUint32(mgm.bufC[mgm.blockSize/2:], uint32(textLen))
	} else {
		binary.BigEndian.PutUint64(mgm.bufC, uint64(adLen))
		binary.BigEndian.PutUint64(mgm.bufC[mgm.blockSize/2:], uint64(textLen))
	}
	xor(mgm.sum, mgm.sum, mgm.mul(mgm.bufP, mgm.bufC))
	mgm.cipher.Encrypt(mgm.bufP, mgm.sum)
	copy(out, mgm.bufP[:mgm.tagSize])
}

func (mgm *MGM) crypt(out, in []byte) {
	mgm.icn[0] &= 0x7F
	mgm.cipher.Encrypt(mgm.bufP, mgm.icn)
	for len(in) >= mgm.blockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(out, mgm.bufC, in)
		incr(mgm.bufP[mgm.blockSize/2:])
		out = out[mgm.blockSize:]
		in = in[mgm.blockSize:]
	}
	if len(in) > 0 {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(out, in, mgm.bufC)
	}
}

func (mgm *MGM) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, []byte) {
	mgm.validateNonce(nonce)
	mgm.validateSizes(plaintext, additionalData)
	if uint64(len(plaintext)) > mgm.maxSize {
		panic("plaintext is too big")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+mgm.tagSize)
	copy(mgm.icn, nonce)
	mgm.crypt(out, plaintext)
	mgm.auth(
		out[len(plaintext):len(plaintext)+mgm.tagSize],
		out[:len(plaintext)],
		additionalData,
	)
	return ret, out
}

func (mgm *MGM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	mgm.validateNonce(nonce)
	mgm.validateSizes(ciphertext, additionalData)
	if uint64(len(ciphertext)-mgm.tagSize) > mgm.maxSize {
		panic("ciphertext is too big")
	}
	ret, out := sliceForAppend(dst, len(ciphertext)-mgm.tagSize)
	ct := ciphertext[:len(ciphertext)-mgm.tagSize]
	copy(mgm.icn, nonce)
	mgm.auth(mgm.sum, ct, additionalData)
	if !hmac.Equal(mgm.sum[:mgm.tagSize], ciphertext[len(ciphertext)-mgm.tagSize:]) {
		return nil, errors.New("invalid authentication tag")
	}
	mgm.crypt(out, ct)
	return ret, nil
}

func CreateVerificationCode(ciphertext, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	ciphertextMac := mac.Sum(nil)

	return ciphertextMac[:8]
}
