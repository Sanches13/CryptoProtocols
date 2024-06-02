package xorshiftplus

import "encoding/binary"

const (
	SeedSize = 16
)

type XorShiftPlus struct {
	seed [SeedSize]byte
}

func New(seed [SeedSize]byte) *XorShiftPlus {
	return &XorShiftPlus{seed: seed}
}

func (x *XorShiftPlus) NextState() uint64 {
	s1 := binary.BigEndian.Uint64(x.seed[0 : SeedSize/2])
	s0 := binary.BigEndian.Uint64(x.seed[SeedSize/2:])

	s1 ^= s1 << 23
	s1 = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5)

	binary.BigEndian.PutUint64(x.seed[:SeedSize/2], s0)
	binary.BigEndian.PutUint64(x.seed[SeedSize/2:], s1)

	return s1 + s0
}
