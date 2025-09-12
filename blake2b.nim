import std/[bitops, strutils]


type
  Blake2bCtx* = object
    state:      array[8, uint64] # hash state
    offset:     array[2, uint64] # offset counters
    buffer:     array[128, byte] # input buffer
    bufferIdx:  uint8            # track data in buffer
    digestSize: int

const
  blockSize     = 128 # buffer size
  rounds        = 12  # number of compression rounds
  maxDigestSize = 64
  maxKeySize    = 64
  maxSaltSize   = 16
  maxPersonSize = 16
  wordBits      = 64  # bits in word
  wordsInBlock  = 16
  wordsInState  = 8
  
  # NOTE: rotation constants
  R1 = 32
  R2 = 24
  R3 = 16
  R4 = 63
  
  IV: array[8, uint64] = [
    0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64,
    0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
    0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64,
    0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
  ]

  # NOTE: sigma array (permutation)
  Sigma: array[12, array[16, int]] = [
    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 ],
    [ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 ],
    [ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 ],
    [ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 ],
    [ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 ],
    [ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 ],
    [ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 ],
    [ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 ],
    [ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 ],
    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 ]
  ]


proc toLittleEndian64(input: openArray[byte], start: int): uint64 =
  for i in 0 ..< 8:
    result = result or (uint64(input[start + i]) shl (i * 8))


func G(v: var array[16, uint64], a, b, c, d: int, x, y: uint64) =
  ## blake2b version
  v[a] = v[a] + v[b] + x
  v[d] = rotateRightBits(v[d] xor v[a], R1)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], R2)
  v[a] = v[a] + v[b] + y
  v[d] = rotateRightBits(v[d] xor v[a], R3)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], R4)


proc compress(ctx: var Blake2bCtx, lastBlock: bool = false) =
  # NOTE: transfer buffer to uint64 array in little-endian format
  var m: array[16, uint64]
  for i in 0 ..< 16:
    m[i] = toLittleEndian64(ctx.buffer, i * 8)

  # NOTE: prepare the message schedule
  var v: array[16, uint64]
  for i in 0 ..< 8:
    v[i] = ctx.state[i]         # initialize v[0..7] with the current hash state
    v[i + wordsInState] = IV[i] # initialize v[8..15] with IV
  
  # NOTE: XOR with offset counters
  v[12] = v[12] xor ctx.offset[0]
  v[13] = v[13] xor ctx.offset[1]
  
  if lastBlock:
    v[14] = not v[14]

  # NOTE: compression
  for i in 0 ..< rounds:
    G(v, 0, 4, 8,  12, m[Sigma[i][0]],  m[Sigma[i][1]])
    G(v, 1, 5, 9,  13, m[Sigma[i][2]],  m[Sigma[i][3]])
    G(v, 2, 6, 10, 14, m[Sigma[i][4]],  m[Sigma[i][5]])
    G(v, 3, 7, 11, 15, m[Sigma[i][6]],  m[Sigma[i][7]])
    
    G(v, 0, 5, 10, 15, m[Sigma[i][8]],  m[Sigma[i][9]])
    G(v, 1, 6, 11, 12, m[Sigma[i][10]], m[Sigma[i][11]])
    G(v, 2, 7, 8,  13, m[Sigma[i][12]], m[Sigma[i][13]])
    G(v, 3, 4, 9,  14, m[Sigma[i][14]], m[Sigma[i][15]])

  # NOTE: update the state with the results of the compression
  for i in 0 ..< wordsInState:
    ctx.state[i] = ctx.state[i] xor v[i] xor v[i + wordsInState]
  
  ctx.bufferIdx = 0


proc copyBlakeCtx(toThisCtx: var Blake2bCtx, fromThisCtx: Blake2bCtx) =
  for i, b in fromThisCtx.state:
    toThisCtx.state[i] = b
  
  for i, b in fromThisCtx.buffer:
    toThisCtx.buffer[i] = b

  toThisCtx.offset[0]    = fromThisCtx.offset[0]
  toThisCtx.offset[1]    = fromThisCtx.offset[1]

  toThisCtx.bufferIdx  = fromThisCtx.bufferIdx
  toThisCtx.digestSize = fromThisCtx.digestSize


proc incOffset(ctx: var Blake2bCtx, increment: uint8) =
   ctx.offset[0] = ctx.offset[0] + increment
   if (ctx.offset[0] < increment): inc ctx.offset[1]


proc padBuffer(ctx: var Blake2bCtx) =
  ## fill remainder of buffer with zeros
  for i in ctx.bufferIdx ..< blockSize:
    ctx.buffer[i] = 0'u8


proc update*[T](ctx: var Blake2bCtx, msg: openArray[T]) {.inline.} =
  ## copy message into buffer and process as it fills.
  for i in 0 ..< msg.len:
    if ctx.bufferIdx == blockSize:
      ctx.incOffset(ctx.bufferIdx)
      ctx.compress()
    ctx.buffer[ctx.bufferIdx] = uint8(msg[i])
    inc ctx.bufferIdx


proc finalize(ctx: var Blake2bCtx) =
  ## pad and compress any remaining data in the buffer
  ctx.incOffset(ctx.bufferIdx)
  ctx.padBuffer()
  ctx.compress(lastBlock = true)


proc digest*(ctx: Blake2bCtx): seq[byte] =
  ## produces a byte seq of length digestSize
  ## does not alter hash state
  var tempCtx: Blake2bCtx
  copyBlakeCtx(tempCtx, ctx)
  
  tempCtx.finalize()

  result = newSeq[byte](tempCtx.digestSize)
  for i in 0 ..< tempCtx.digestSize:
    result[i] = byte((tempCtx.state[i div 8] shr (8 * (i mod 8))) and 0xFF)


proc hexDigest*(ctx: Blake2bCtx): string =
  ## produces a hex string of length digestSize * 2
  ## does not alter hash state
  let digest = ctx.digest()
  
  result = newStringOfCap(digest.len + digest.len)
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc initBlake2bCtx(ctx: var Blake2bCtx, key, salt, personal: openArray[byte], digestSize: int) =
  if not (digestSize <= maxDigestSize):
    raise newException(ValueError, "digest size exceeds maximum $1 bytes" % $maxDigestSize)
  ctx.digestSize = digestSize
  
  # NOTE: initialize hash state with IV
  for i in 0 ..< wordsInState:
    ctx.state[i] = IV[i]
  
  # NOTE: prep parameter block
  var P: array[16, uint64]
  
  # NOTE: initialize the first 64-bit word of the parameter block
  P[0] = uint64(0x01010000) xor (uint64(key.len) shl 8) xor uint64(ctx.digestSize)

  # NOTE: copy salt and personalization into the parameter block
  if salt.len > 0:
    if not (salt.len <= maxSaltSize):
      raise newException(ValueError, "salt size exceeds maximum $1 bytes" % $maxSaltSize) 
    copyMem(addr P[4], unsafeAddr salt[0], salt.len)

  if personal.len > 0:
    if not (personal.len <= maxPersonSize):
      raise newException(ValueError, "personalization size exceeds maximum $1 bytes" % $maxPersonSize)
    copyMem(addr P[6], unsafeAddr personal[0], personal.len)
  
  # NOTE: XOR state with the first 8 words of the parameter block
  for i in 0 ..< wordsInState:
    ctx.state[i] = ctx.state[i] xor P[i]
  
  # NOTE: pad key and add to buffer
  if key.len > 0:
    if not (key.len <= maxKeySize):
      raise newException(ValueError, "key size exceeds maximum $1 bytes" % $maxKeySize)
    var padKey: array[blockSize, uint8]
    copyMem(addr padKey[0], unsafeAddr key[0], key.len)
    ctx.update(padKey)


proc newBlake2bCtx*(
  msg: openArray[byte] = @[],
  key: openArray[byte] = @[],
  salt: openArray[byte] = @[],
  personal: openArray[byte] = @[],
  digestSize: int = maxDigestSize
): Blake2bCtx =
  var ctx: Blake2bCtx
  initBlake2bCtx(ctx, key, salt, personal, digestSize)
  if msg.len > 0:
    ctx.update(msg)

  return ctx


proc newBlake2bCtx*(
  msg: string,
  key: string = "",
  salt: string = "",
  personal: string = "",
  digestSize: int = maxDigestSize
): Blake2bCtx =
  return newBlake2bCtx(
    msg.toOpenArrayByte(0, msg.len.pred), 
    key.toOpenArrayByte(0, key.len.pred),
    salt.toOpenArrayByte(0, salt.len.pred),
    personal.toOpenArrayByte(0, personal.len.pred),
    digestSize
  )
