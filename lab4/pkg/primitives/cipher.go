package primitives

const (
	BlockSize = 8
	KeySize   = 32
)

type nv uint32

func (n nv) shift11() nv {
	return ((n << 11) & (1<<32 - 1)) | ((n >> (32 - 11)) & (1<<32 - 1))
}

type Seq []uint8

var (
	SeqEncrypt = Seq([]uint8{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
	})
	SeqDecrypt = Seq([]uint8{
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
	})
)

type Cipher struct {
	key  [KeySize]byte
	sbox *Sbox
	x    [8]nv
}

func (c *Cipher) Clear() {
	for i := 0; i < 8; i++ {
		c.x[i] = 0
	}
	for i := 0; i < KeySize; i++ {
		c.key[i] = 0
	}
}

func NewCipher(key []byte, sbox *Sbox) *Cipher {
	if len(key) != KeySize {
		panic("invalid key size")
	}
	c := Cipher{sbox: sbox}
	copy(c.key[:], key)
	c.x = [8]nv{
		nv(key[0]) | nv(key[1])<<8 | nv(key[2])<<16 | nv(key[3])<<24,
		nv(key[4]) | nv(key[5])<<8 | nv(key[6])<<16 | nv(key[7])<<24,
		nv(key[8]) | nv(key[9])<<8 | nv(key[10])<<16 | nv(key[11])<<24,
		nv(key[12]) | nv(key[13])<<8 | nv(key[14])<<16 | nv(key[15])<<24,
		nv(key[16]) | nv(key[17])<<8 | nv(key[18])<<16 | nv(key[19])<<24,
		nv(key[20]) | nv(key[21])<<8 | nv(key[22])<<16 | nv(key[23])<<24,
		nv(key[24]) | nv(key[25])<<8 | nv(key[26])<<16 | nv(key[27])<<24,
		nv(key[28]) | nv(key[29])<<8 | nv(key[30])<<16 | nv(key[31])<<24,
	}
	return &c
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

// Convert binary byte block to two 32-bit internal integers.
func block2nvs(b []byte) (n1, n2 nv) {
	n1 = nv(b[0]) | nv(b[1])<<8 | nv(b[2])<<16 | nv(b[3])<<24
	n2 = nv(b[4]) | nv(b[5])<<8 | nv(b[6])<<16 | nv(b[7])<<24
	return
}

// Convert two 32-bit internal integers to binary byte block.
func nvs2block(n1, n2 nv, b []byte) {
	b[0] = byte((n2 >> 0) & 255)
	b[1] = byte((n2 >> 8) & 255)
	b[2] = byte((n2 >> 16) & 255)
	b[3] = byte((n2 >> 24) & 255)
	b[4] = byte((n1 >> 0) & 255)
	b[5] = byte((n1 >> 8) & 255)
	b[6] = byte((n1 >> 16) & 255)
	b[7] = byte((n1 >> 24) & 255)
}

func (c *Cipher) xcrypt(seq Seq, n1, n2 nv) (nv, nv) {
	for _, i := range seq {
		n1, n2 = c.sbox.k(n1+c.x[i]).shift11()^n2, n1
	}
	return n1, n2
}

// Encrypt single block.
// If provided slices are shorter than the block size, then it will panic.
func (c *Cipher) Encrypt(dst, src []byte) {
	n1, n2 := block2nvs(src)
	n1, n2 = c.xcrypt(SeqEncrypt, n1, n2)
	nvs2block(n1, n2, dst)
}

// Decrypt single block.
// If provided slices are shorter than the block size, then it will panic.
func (c *Cipher) Decrypt(dst, src []byte) {
	n1, n2 := block2nvs(src)
	n1, n2 = c.xcrypt(SeqDecrypt, n1, n2)
	nvs2block(n1, n2, dst)
}
