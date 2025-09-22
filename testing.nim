proc blamka(v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11, v12, v13, v14, v15: var Word) =
  #[
    BlaMka: optimized data mixing operation for Argon2
    + designed to increase the computational cost in a way
    that is resistant to optimization by parallel computing hardware.
  ]#
  
  v00 = v00 + v04 + 2*uint64(uint32(v00))*uint64(uint32(v04))
  v12 = v12 xor v00
  v12 = v12 shr 32 or v12 shl 32
  v08 = v08 + v12 + 2*uint64(uint32(v08))*uint64(uint32(v12))
  v04 = v04 xor v08
  v04 = v04 shr 24 or v04 shl 40

  v00 = v00 +  v04 + 2*uint64(uint32(v00))*uint64(uint32(v04))
  v12 = v12 xor v00
  v12 = v12 shr 16 or v12 shl 48
  v08 = v08 + v12 + 2*uint64(uint32(v08))*uint64(uint32(v12))
  v04 = v04 xor v08
  v04 = v04 shr 63 or v04 shl 1

  v01 = v01 + v05 + 2*uint64(uint32(v01))*uint64(uint32(v05))
  v13 = v13 xor v01
  v13 = v13 shr 32 or v13 shl 32
  v09 = v09 + v13 + 2*uint64(uint32(v09))*uint64(uint32(v13))
  v05 = v05 xor v09
  v05 = v05 shr 24 or v05 shl 40

  v01 = v01 + v05 + 2*uint64(uint32(v01))*uint64(uint32(v05))
  v13 = v13 xor v01
  v13 = v13 shr 16 or v13 shl 48
  v09 = v09 + v13 + 2*uint64(uint32(v09))*uint64(uint32(v13))
  v05 = v05 xor v09
  v05 = v05 shr 63 or v05 shl 1

  v02 = v02 + v06 + 2*uint64(uint32(v02))*uint64(uint32(v06))
  v14 = v14 xor v02
  v14 = v14 shr 32 or v14 shl 32
  v10 = v10 + v14 + 2*uint64(uint32(v10))*uint64(uint32(v14))
  v06 = v06 xor v10
  v06 = v06 shr 24 or v06 shl 40

  v02 = v02 + v06 + 2*uint64(uint32(v02))*uint64(uint32(v06))
  v14 = v14 xor v02
  v14 = v14 shr 16 or v14 shl 48
  v10 = v10 + v14 + 2*uint64(uint32(v10))*uint64(uint32(v14))
  v06 = v06 xor v10
  v06 = v06 shr 63 or v06 shl 1

  v03 = v03 + v07 + 2*uint64(uint32(v03))*uint64(uint32(v07))
  v15 = v15 xor v03
  v15 = v15 shr 32 or v15 shl 32
  v11 = v11 + v15 + 2*uint64(uint32(v11))*uint64(uint32(v15))
  v07 = v07 xor v11
  v07 = v07 shr 24 or v07 shl 40

  v03 = v03 + v07 + 2*uint64(uint32(v03))*uint64(uint32(v07))
  v15 = v15 xor v03
  v15 = v15 shr 16 or v15 shl 48
  v11 = v11 + v15 + 2*uint64(uint32(v11))*uint64(uint32(v15))
  v07 = v07 xor v11
  v07 = v07 shr 63 or v07 shl 1

  v00 = v00 + v05 + 2*uint64(uint32(v00))*uint64(uint32(v05))
  v15 = v15 xor v00
  v15 = v15 shr 32 or v15 shl 32
  v10 = v10 + v15 + 2*uint64(uint32(v10))*uint64(uint32(v15))
  v05 = v05 xor v10
  v05 = v05 shr 24 or v05 shl 40

  v00 = v00 + v05 + 2*uint64(uint32(v00))*uint64(uint32(v05))
  v15 = v15 xor v00
  v15 = v15 shr 16 or v15 shl 48
  v10 = v10 + v15 + 2*uint64(uint32(v10))*uint64(uint32(v15))
  v05 = v05 xor v10
  v05 = v05 shr 63 or v05 shl 1

  v01 = v01 + v06 + 2*uint64(uint32(v01))*uint64(uint32(v06))
  v12 = v12 xor v01
  v12 = v12 shr 32 or v12 shl 32
  v11 = v11 + v12 + 2*uint64(uint32(v11))*uint64(uint32(v12))
  v06 = v06 xor v11
  v06 = v06 shr 24 or v06 shl 40

  v01 = v01 + v06 + 2*uint64(uint32(v01))*uint64(uint32(v06))
  v12 = v12 xor v01
  v12 = v12 shr 16 or v12 shl 48
  v11 = v11 + v12 + 2*uint64(uint32(v11))*uint64(uint32(v12))
  v06 = v06 xor v11
  v06 = v06 shr 63 or v06 shl 1

  v02 = v02 + v07 + 2*uint64(uint32(v02))*uint64(uint32(v07))
  v13 = v13 xor v02
  v13 = v13 shr 32 or v13 shl 32
  v08 = v08 + v13 + 2*uint64(uint32(v08))*uint64(uint32(v13))
  v07 = v07 xor v08
  v07 = v07 shr 24 or v07 shl 40

  v02 = v02 + v07 + 2*uint64(uint32(v02))*uint64(uint32(v07))
  v13 = v13 xor v02
  v13 = v13 shr 16 or v13 shl 48
  v08 = v08 + v13 + 2*uint64(uint32(v08))*uint64(uint32(v13))
  v07 = v07 xor v08
  v07 = v07 shr 63 or v07 shl 1

  v03 = v03 + v04 + 2*uint64(uint32(v03))*uint64(uint32(v04))
  v14 = v14 xor v03
  v14 = v14 shr 32 or v14 shl 32
  v09 = v09 + v14 + 2*uint64(uint32(v09))*uint64(uint32(v14))
  v04 = v04 xor v09
  v04 = v04 shr 24 or v04 shl 40

  v03 = v03 + v04 + 2*uint64(uint32(v03))*uint64(uint32(v04))
  v14 = v14 xor v03
  v14 = v14 shr 16 or v14 shl 48
  v09 = v09 + v14 + 2*uint64(uint32(v09))*uint64(uint32(v14))
  v04 = v04 xor v09
  v04 = v04 shr 63 or v04 shl 1


proc processBlockGeneric(dest: var Block, in1, in2: Block, doXOR: bool) =
  #[
    processes a block of data using the BlaMka function
    
    dest: block where the result is stored
    in1, in2: blocks to be processed
  ]#
  var t: Block

  # NOTE: XOR in1 and in2 into t
  for i in 0 ..< blockSize:
    t[i] = in1[i] xor in2[i]

  # NOTE: row-wise processing
  for i in countup(0, blockSize.pred, 16):
    blamka(
      t[i],    t[i+1],  t[i+2],  t[i+3],
      t[i+4],  t[i+5],  t[i+6],  t[i+7],
      t[i+8],  t[i+9],  t[i+10], t[i+11],
      t[i+12], t[i+13], t[i+14], t[i+15]
    )

  # NOTE: column-wise processing
  for i in countup(0, int(blockSize/8).pred, 2):
    blamka(
      t[i],     t[i+1],      t[i+16],  t[i+16+1],
      t[i+32],  t[i+32+1],   t[i+48],  t[i+48+1],
      t[i+64],  t[i+64+1],   t[i+80],  t[i+80+1],
      t[i+96],  t[i+96+1],   t[i+112], t[i+112+1]
    )

  # NOTE: final XOR (helps ensure non-linearity)
  for i in 0 ..< 128:
    if doXOR:
      dest[i] = dest[i] xor in1[i] xor in2[i] xor t[i]
    else:
      dest[i] = in1[i] xor in2[i] xor t[i]


proc processBlock(dest: var Block, in1, in2: Block) =
  processBlockGeneric(dest, in1, in2, false)


proc processBlockXOR(dest: var Block, in1, in2: Block) =
  processBlockGeneric(dest, in1, in2, true)
