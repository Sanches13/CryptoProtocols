package mgm

func (mgm *MGM) mul(xBuf, yBuf []byte) []byte {
	mgm.x.SetBytes(xBuf)
	mgm.y.SetBytes(yBuf)
	mgm.z.SetInt64(0)
	var i int
	for mgm.y.BitLen() != 0 {
		if mgm.y.Bit(0) == 1 {
			mgm.z.Xor(mgm.z, mgm.x)
		}
		if mgm.x.Bit(mgm.maxBit) == 1 {
			mgm.x.SetBit(mgm.x, mgm.maxBit, 0)
			mgm.x.Lsh(mgm.x, 1)
			mgm.x.Xor(mgm.x, mgm.r)
		} else {
			mgm.x.Lsh(mgm.x, 1)
		}
		mgm.y.Rsh(mgm.y, 1)
	}
	zBytes := mgm.z.Bytes()
	rem := len(xBuf) - len(zBytes)
	for i = 0; i < rem; i++ {
		mgm.mulBuf[i] = 0
	}
	copy(mgm.mulBuf[rem:], zBytes)
	return mgm.mulBuf
}
