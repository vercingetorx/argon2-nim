import std/[base64, sequtils, strformat, strutils]

import blake2b


#[
General:

  + Argon2 RFC: https://www.rfc-editor.org/rfc/rfc9106.txt
  + This implementation is based heavily on https://cs.opensource.google/go/x/crypto/+/master:argon2/
  + Thoroughly commented for algorithm flow and comprehension

Modes:

  + Argon2d (Data-Dependent Memory Access):
    Argon2d uses data-dependent memory access, which means the sequence of references to memory blocks depends on the block contents.
    Faster but more vulnerable to side-channel attacks.

  + Argon2i (Data-Independent Memory Access):
    Argon2i uses data-independent memory access, meaning the sequence of references to the memory blocks is precomputed and independent of the actual block contents.
    Provides resistence to side-channel attacks.

  + Argon2id (Hybrid):
    Argon2id combines both approaches: it starts like Argon2i (data-independent) and then switches to Argon2d (data-dependent).
    This mode aims to provide a balance between resistance to side-channel attacks and computational efficiency (GPU attacks).

Parameters: (via RFC)

  + Message string P, which is a password for password hashing
    applications.  It MUST have a length not greater than 2^(32)-1
    bytes.

  + Nonce S, which is a salt for password hashing applications.  It
    MUST have a length not greater than 2^(32)-1 bytes.  16 bytes is
    RECOMMENDED for password hashing.  The salt SHOULD be unique for
    each password.

  + Degree of parallelism p determines how many independent (but
    synchronizing) computational chains (lanes) can be run.  It MUST
    be an integer value from 1 to 2^(24)-1.

  + Tag length T MUST be an integer number of bytes from 4 to 2^(32)-
    1.

  + Memory size m MUST be an integer number of kibibytes from 8*p to
    2^(32)-1.  The actual number of blocks is m', which is m rounded
    down to the nearest multiple of 4*p.

  + Number of passes t (used to tune the running time independently of
    the memory size) MUST be an integer number from 1 to 2^(32)-1.

  + Version number v MUST be one byte 0x13.

  Secret value K is OPTIONAL. If used, it MUST have a length not
  greater than 2^(32)-1 bytes.

  Associated data X is OPTIONAL. If used, it MUST have a length not
  greater than 2^(32)-1 bytes.

  Type y MUST be 0 for Argon2d, 1 for Argon2i, or 2 for Argon2id.


Configuration:

  OWASP recommends Argon2id with these settings: (https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Password_Storage_Cheat_Sheet.md)
  
  m=47104 (46 MiB), t=1, p=1 (Do not use with Argon2i)
  m=19456 (19 MiB), t=2, p=1 (Do not use with Argon2i)
  m=12288 (12 MiB), t=3, p=1
  m=9216  (9 MiB),  t=4, p=1
  m=7168  (7 MiB),  t=5, p=1
  
  "These configuration settings provide an equal level of defense, and the only difference is a trade off between CPU and RAM usage."

TODO:
  
  + add memory clearing (clear/reset proc?)
  + optimizations and inlining
]#

const
  blockSize: int = 128
  blockSizeInBytes: int = 1024
  blake2bMaxDigestSize: int = 64
  # NOTE: synchronization points are specific positions in the algorithm's execution where the memory
  # state is synchronized across different computational threads or lanes.
  syncPoints: uint32 = 4
  Argon2_Version_1_3: int = 0x13    # 19 in decimal
  Argon2_Version_1_2_1: int = 0x10  # 16 in decimal

type
  Word = uint64
  Block = array[blockSize, Word] # 128(Words per Block) × 8(bytes per Word) = 1024 byte(block size)
  MemoryArray = seq[Block]
  Mode = enum
    ARGON2D, ARGON2I, ARGON2ID # 0, 1, 2 in decimal
  Argon2Params = object
    password: seq[byte]
    salt: seq[byte]
    secret: seq[byte]
    assocData: seq[byte]
    memoryCost: uint32        # memory cost (in kibibytes)
    timeCost: uint32          # time cost (number of iterations)
    parallelism: uint32       # degree of parallelism (number of threads)
    digestSize: uint32        # desired length of the final hash
    version: int
    mode: Mode
  Argon2Ctx = object
    params: Argon2Params
    mArray: MemoryArray
    memory: ptr MemoryArray


include blamka

##########################################################################

proc validateArgon2Params(params: Argon2Params) =
  if not (params.parallelism > 0 and params.parallelism <= (1 shl 24) - 1):
   raise newException(ValueError, "Parallelism must be between 1 and 2^24 - 1")

  # NOTE: must be a power of 2 greater than 1
  if not (params.memoryCost >= 8 * params.parallelism and params.memoryCost <= (1 shl 32) - 1):
    raise newException(ValueError, "Memory cost must be between 8 * parallelism and 2^32 - 1")

  if not (params.timeCost > 0 and params.timeCost <= (1 shl 32) - 1):
    raise newException(ValueError, "Time cost must be between 1 and 2^32 - 1")

  if not (params.digestSize >= 4 and params.digestSize <= (1 shl 32) - 1):
    raise newException(ValueError, "Hash length must be between 4 and 2^32 - 1")

  if not ([Argon2_Version_1_3, Argon2_Version_1_2_1].contains(params.version)):
    raise newException(ValueError, "Version must be either 0x13 (19) or 0x10 (16)")

  if not ([ARGON2D, ARGON2I, ARGON2ID].contains(params.mode)):
    raise newException(ValueError, "Mode must be one of ARGON2D (0), ARGON2I (1), or ARGON2ID (2)")


proc toBytesLE(value: uint32): seq[byte] =
  ## convert a 32-bit unsigned integer to a sequence of bytes in little-endian order
  result = newSeq[byte](sizeof(value))
  for i in 0 ..< sizeof(value):
    result[i] = byte((value shr (8 * i)) and 0xFF)


proc bytesToBlock(bytes: seq[byte]): Block =
  # NOTE: input byte sequence must be 1024 bytes long for Block conversion
  var word: Word
  for i in 0 ..< blockSize:  # 128 Words (uint64) in a Block
    word = 0
    for j in 0 ..< 8:  # 8 bytes in a Word
      word = word or (Word(bytes[i * 8 + j]) shl (j * 8))
    result[i] = word
  return result


proc blockToBytes(blk: Block): seq[byte] =
  result = newSeq[byte](blockSizeInBytes)
  for i, word in blk:
    for j in 0 ..< 8:  # 8 bytes in a Word
      result[i * 8 + j] = byte((word shr (j * 8)) and 0xFF)

##########################################################################

proc HPrime(input: seq[byte], digestSize: uint32): seq[byte] =
  ## turns BLAKE2 into a variable-length hash function
  result = newSeq[byte](digestSize)
  var V: seq[byte]

  if digestSize <= 64:
    # NOTE: digest size (tag length) is within BLAKE2B's maximum of 64 -> hash input directly
    var blake2bCtx = newBlake2bCtx(digestSize = int(digestSize))
    blake2bCtx.update(toBytesLE(digestSize) & input)
    V = blake2bCtx.digest()
    copyMem(addr result[0], addr V[0], digestSize)
  else:
    # NOTE: digest size (tag length) is larger than BLAKE2B's maximum of 64 -> extend hash artificially
    # NOTE: initial hash
    var blake2bCtx = newBlake2bCtx(digestSize = 64)
    blake2bCtx.update(toBytesLE(digestSize) & input)
    V = blake2bCtx.digest()
    copyMem(addr result[0], addr V[0], 32)
    
    # NOTE: intermediate hashing (extending)
    var remaining = digestSize - 32
    var offset: uint32 = 32
    while remaining > 64:
      blake2bCtx = newBlake2bCtx(digestSize = 64)
      blake2bCtx.update(V)
      V = blake2bCtx.digest()
      let copySize = min(remaining, 32)
      copyMem(addr result[offset], addr V[0], copySize)
      remaining -= copySize
      offset += copySize

    # NOTE: final hash
    blake2bCtx = newBlake2bCtx(digestSize = int(remaining))
    blake2bCtx.update(V)
    V = blake2bCtx.digest()
    copyMem(addr result[offset], addr V[0], remaining)

  return result

##########################################################################

proc initArgon2Params(
  password, salt, secret, assocData: openArray[byte],
  timeCost, memoryCost, parallelism, digestSize, version: int,
  mode: Mode
): Argon2Params =
  
  result.password = toSeq(password)
  result.salt = toSeq(salt)
  result.secret = toSeq(secret)
  result.assocData = toSeq(assocData)
  result.parallelism = uint32(parallelism)
  result.memoryCost = uint32(memoryCost)
  result.timeCost = uint32(timeCost)
  result.digestSize = uint32(digestSize)
  result.version = version
  result.mode = mode


proc initHash(params: Argon2Params): seq[byte] =
  ## create initial hash based on input parameters
  var blake2bCtx = newBlake2bCtx(digestSize = 64)

  # NOTE: convert tuning parameters to bytes in little-endian order and update BLAKE2b state
  blake2bCtx.update(toBytesLE(params.parallelism))
  blake2bCtx.update(toBytesLE(params.digestSize))
  blake2bCtx.update(toBytesLE(params.memoryCost))
  blake2bCtx.update(toBytesLE(params.timeCost))
  blake2bCtx.update(toBytesLE(uint32(params.version)))
  blake2bCtx.update(toBytesLE(uint32(params.mode)))

  # NOTE: update BLAKE2b state with password, salt, secret, and associated data
  blake2bCtx.update(toBytesLE(uint32(params.password.len)))
  blake2bCtx.update(params.password)
  blake2bCtx.update(toBytesLE(uint32(params.salt.len)))
  blake2bCtx.update(params.salt)
  blake2bCtx.update(toBytesLE(uint32(params.secret.len)))
  if params.secret.len > 0:
    blake2bCtx.update(params.secret)
  blake2bCtx.update(toBytesLE(uint32(params.assocData.len)))
  if params.assocData.len > 0:
    blake2bCtx.update(params.assocData)
 
  return blake2bCtx.digest()


proc initMemoryArray(params: var Argon2Params): MemoryArray =
  var mPrime = params.memoryCost

  # NOTE: adjust memory cost to be a multiple of syncPoints * parallelism
  mPrime = mPrime div (syncPoints * params.parallelism) * (syncPoints * params.parallelism)
  if mPrime < 2 * syncPoints * params.parallelism:
    mPrime = 2 * syncPoints * params.parallelism
  params.memoryCost = mPrime
  
  # NOTE: initialize memory array with adjusted number of blocks (cost)
  result = newSeq[Block](params.memoryCost)
  # NOTE: zeroing the memory is not necessary as Nim initializes with zeros by default


proc initBlocks(ctx: var Argon2Ctx, h0: seq[byte]) =
  #[
    initializes the first two blocks in each lane

    h0: initial hash value
  ]#
  var blk: Block
  var bts: seq[byte]
  var modifiedH0: seq[byte]

  for lane in 0 ..< ctx.params.parallelism:
    let laneOffset = lane * (ctx.params.memoryCost div ctx.params.parallelism)
    # NOTE: make a copy of the initial hash and extend it
    modifiedH0 = h0
    # QUESTION: should we set length when the hash is generated?
    modifiedH0.setLen(h0.len + 8)

    # NOTE: convert the lane number to bytes in little-endian format and add to extended hash
    bts = toBytesLE(lane)
    copyMem(addr modifiedH0[blake2bMaxDigestSize + 4], addr bts[0], bts.len)
    
    # NOTE: add block index 0 to the extended hash -> compute the block -> update memory
    bts = toBytesLE(uint32(0))
    copyMem(addr modifiedH0[blake2bMaxDigestSize], addr bts[0], bts.len)
    blk = bytesToBlock(HPrime(modifiedH0, uint32(blockSizeInBytes)))
    ctx.memory[][laneOffset + 0] = blk
    
    # NOTE: repeat for block index 1
    bts = toBytesLE(uint32(1))
    copyMem(addr modifiedH0[blake2bMaxDigestSize], addr bts[0], bts.len)
    blk = bytesToBlock(HPrime(modifiedH0, uint32(blockSizeInBytes)))
    ctx.memory[][laneOffset + 1] = blk

##########################################################################

proc getSyncPoints(mode: Mode): int =
  # NOTE: unused as we hardcode to 4 for all modes in line with Go's implementation.
  case mode
  of ARGON2D:
    return 1
  of ARGON2I, ARGON2ID:
    return 4


proc phi(rand, m, s: uint64; lane, lanes: uint32): uint32 =
  #[
    calculates a pseudo-random index for memory segment processing
    
    rand:  64-bit pseudo-random value used as the base for index calculation
    m:     modifier value derived from the number of segments and other parameters
    s:     start point for the segment calculation, influenced by the slice and segment count
    lane:  current processing lane
    lanes: total number of lanes
    
    returns: uint32 index
  ]#
  # NOTE: extract the lower 32 bits of the random value
  var p = rand and 0xFFFFFFFF'u64
  # NOTE: square the value and shift right to fit 32-bit
  p = (p * p) shr 32
  # NOTE: multiply by modifier m and adjust to 32-bit
  p = (p * m) shr 32
  # NOTE: final index calculation
  return lane * lanes + uint32((s + m - (p + 1)) mod lanes)


proc indexAlpha(rand: uint64; lanes, segments, threads, n, slice, lane, index: uint32): uint32 =
  #[
    computes a reference index within a lane
    
    rand:     64-bit pseudo-random value
    lanes:    total number of lanes
    segments: number of segments per lane
    threads:  number of threads (parallelism)
    n:        current pass number
    slice:    current slice number
    lane:     current processing lane
    index:    current index within the lane
    
    returns: uint32 index
  ]#
  # NOTE: determine reference lane
  var refLane = uint32(rand shr 32) mod threads
  # NOTE: first slice of the first pass
  if n == 0 and slice == 0:
    refLane = lane
  
  # NOTE: calculate base modifier
  var m = 3 * segments
  # NOTE: calculate start point
  var s = ((slice + 1) mod syncPoints) * segments
  # NOTE: adjust m if the current lane is the reference lane
  if lane == refLane:
    m += index
  
  # NOTE: first pass
  if n == 0:
    m = slice * segments
    s = 0
    if slice == 0 or lane == refLane:
      m += index
  
  # NOTE: adjust m for the first index or if in the reference lane
  if index == 0 or lane == refLane:
    m -= 1

  return phi(rand, uint64(m), uint64(s), refLane, lanes)


proc processSegment(params: tuple[memory: ptr MemoryArray, n, slice, lane, lanes, segments, parallelism, memoryCost, timeCost: uint32, mode: Mode]) {.thread.} =
  ## processes a single segment of a lane in the memory array
  var addresses, input, zero: Block
  # NOTE: initialize the input block for Argon2i or first half of Argon2id
  if params.mode == ARGON2I or (params.mode == ARGON2ID and params.n == 0 and params.slice < syncPoints div 2):
    input[0] = uint64(params.n)
    input[1] = uint64(params.lane)
    input[2] = uint64(params.slice)
    input[3] = uint64(params.memoryCost)
    input[4] = uint64(params.timeCost)
    input[5] = uint64(params.mode)

  var index: uint32 = 0
  if params.n == 0 and params.slice == 0:
    # NOTE: skip first two blocks that are already initialized
    index = 2
    # NOTE: for Argon2i and first half of Argon2id, initialize the address block
    if params.mode == ARGON2I or params.mode == ARGON2ID:
      inc input[6]
      processBlock(addresses, input, zero)
      processBlock(addresses, addresses, zero)

  # NOTE: calculate the starting offset in the memory array for this segment
  var offset = params.lane * params.lanes + params.slice * params.segments + index
  var random: uint64
  while index < params.segments:
    var prev = offset.pred
    # NOTE: first block of the first slice
    if index == 0 and params.slice == 0:
      # NOTE: select last block in lane
      prev += params.lanes
    
    # NOTE: generate pseudo-random values for indexing (mode dependant)
    if params.mode == ARGON2I or (params.mode == ARGON2ID and params.n == 0 and params.slice < syncPoints div 2):
      if int(index) mod blockSize == 0:
        # NOTE: refresh the address block periodically
        inc input[6]
        processBlock(addresses, input, zero)
        processBlock(addresses, addresses, zero)
      random = addresses[int(index) mod blockSize]
    else:
      # NOTE: for Argon2d and second half of Argon2id, use the previous block's first word
      random = params.memory[][prev][0]
    
    # NOTE: calculate the index of the new block to reference
    let newOffset = indexAlpha(random, params.lanes, params.segments, params.parallelism, params.n, params.slice, params.lane, index)
    # NOTE: XOR the current block with the referenced block and the previous block
    processBlockXOR(params.memory[][offset], params.memory[][prev], params.memory[][newOffset])
    
    inc index
    inc offset


proc processBlocks(ctx: Argon2Ctx) =
  ## spawn threads for parallel computation across different lanes and slices
  let lanes = ctx.params.memoryCost div ctx.params.parallelism
  let segments = lanes div syncPoints

  var threads = newSeq[Thread[tuple[memory: ptr MemoryArray, n, slice, lane, lanes, segments, parallelism, memoryCost, timeCost: uint32, mode: Mode]]](ctx.params.parallelism)

  for n in 0 ..< ctx.params.timeCost:
    for slice in 0 ..< syncPoints:
      for lane in 0 ..< ctx.params.parallelism:
        createThread(threads[lane], processSegment, (ctx.memory, n, slice, lane, lanes, segments, ctx.params.parallelism, ctx.params.memoryCost, ctx.params.timeCost, ctx.params.mode))
      joinThreads(threads)

##########################################################################

proc base64Encode[T](data: openarray[T]): string =
  ## convenience proc
  return data.encode().strip(leading=false, chars={'='})


proc digest*(ctx: Argon2Ctx): seq[byte] =
  ## generate final hash from the last block of each lane in memory array
  # NOTE: number of blocks in each lane
  let lanes = ctx.params.memoryCost div ctx.params.parallelism
  var xorFinalBlock: Block
 
  for lane in 0 ..< ctx.params.parallelism:
    let blockIndex = lane * lanes + lanes.pred
    # NOTE: first lane -> init xorFinalBlock
    if lane == 0:
      xorFinalBlock = ctx.memory[][blockIndex]
    # NOTE: XOR each word of the lane's final block with the corresponding word in xorFinalBlock
    else:
      for j in 0 ..< blockSize:
        xorFinalBlock[j] = xorFinalBlock[j] xor ctx.memory[][blockIndex][j]

  # NOTE: convert the XOR-ed final block to bytes
  let finalBlockBytes = blockToBytes(xorFinalBlock)
  # NOTE: use HPrime to construct the final digest
  return HPrime(finalBlockBytes, ctx.params.digestSize)


proc hexDigest*(ctx: Argon2Ctx): string =
  ## generate hex string of length digestSize * 2
  let digest = ctx.digest()
  result = newStringOfCap(digest.len + digest.len)
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())
  return result


proc encoded*(ctx: Argon2Ctx): string =
  ## form encoded string with parameters and base64 encoded salt and digest
  let digest = ctx.digest()
  let strMode = ($ctx.params.mode).toLowerAscii()
  return fmt"${strMode}$v={ctx.params.version}$m={ctx.params.memoryCost},t={ctx.params.timeCost},p={ctx.params.parallelism}${base64Encode(ctx.params.salt)}${base64Encode(digest)}"

##########################################################################

proc newArgon2Ctx*(
  password, salt: openArray[byte],
  secret: openArray[byte] = @[], assocData: openArray[byte] = @[],
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3, 
  mode: Mode = ARGON2ID
): Argon2Ctx =

  result.params = initArgon2Params(
    password, salt, secret, assocData,
    timeCost, memoryCost, parallelism,
    digestSize,
    version,
    mode
  )

  validateArgon2Params(result.params)
  
  # NOTE: create initial hash based on input parameters
  let h0 = initHash(result.params)

  result.mArray = initMemoryArray(result.params)
  result.memory = addr result.mArray
  
  # NOTE: initialize first two blocks in each lane
  result.initBlocks(h0)
  
  # NOTE: fill the memory array in parallel
  result.processBlocks()


proc newArgon2Ctx*(
  password, salt: string,
  secret: string = "", assocData: string = "",
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3, 
  mode: Mode = ARGON2ID
): Argon2Ctx =
  
  return newArgon2Ctx(
    password.toOpenArrayByte(0, password.len.pred),
    salt.toOpenArrayByte(0, salt.len.pred),
    secret.toOpenArrayByte(0, secret.len.pred),
    assocData.toOpenArrayByte(0, assocData.len.pred),
    timeCost, memoryCost, parallelism,
    digestSize,
    version, 
    mode
  )
