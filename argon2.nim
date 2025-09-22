import std/[base64, strutils]

import argon2_core
export argon2_core


## Constant-time equality for byte arrays.
## - Returns true when `a` and `b` have identical length and contents.
## - Runs in time independent of the first differing byte position.
proc ctEqual*(a, b: openArray[byte]): bool =
  var diff = uint8(a.len xor b.len)
  let n = min(a.len, b.len)
  for i in 0 ..< n:
    diff = diff or uint8(a[i] xor b[i])
  result = diff == 0


## Constant-time equality for strings.
## - Intended for ASCII/byte-like strings (no normalization).
## - Comparison is case-sensitive; use toLowerAscii() if needed.
proc ctEqualStrings*(a, b: string): bool =
  var diff = uint8(a.len xor b.len)
  let n = min(a.len, b.len)
  for i in 0 ..< n:
    diff = diff or uint8(ord(a[i]) xor ord(b[i]))
  result = diff == 0


proc base64DecodeNoPad(s: string): seq[byte] =
  var padded = s
  let rem = s.len mod 4
  if rem == 1:
    raise newException(ValueError, "invalid base64 length")
  elif rem == 2:
    padded &= "=="
  elif rem == 3:
    padded &= "="
  let dec = base64.decode(padded) # string
  result = newSeq[byte](dec.len)
  for i, ch in dec:
    result[i] = byte(ch)


## One-shot Argon2 hashing (bytes API).
## - Computes and returns the raw digest bytes.
## - Clears internal buffers after computation.
## Params:
##   password, salt: input byte arrays (salt should be unique per password).
##   secret, assocData: optional key and associated data per RFC 9106.
##   timeCost, memoryCost, parallelism: tuning parameters.
##   digestSize: desired tag length in bytes.
##   version: Argon2 version (e.g., Argon2_Version_1_3).
##   mode: ARGON2D, ARGON2I, or ARGON2ID.
proc argon2Hash*(
  password, salt: openArray[byte],
  secret: openArray[byte] = @[],
  assocData: openArray[byte] = @[],
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): seq[byte] =
  var ctx = newArgon2Ctx(
    password, salt, secret, assocData,
    timeCost, memoryCost, parallelism,
    digestSize, version, mode
  )
  let output = ctx.digest()
  ctx.reset()
  return output


## One-shot Argon2 hashing to lowercase hex (bytes API).
## - Returns a hex string of length `2 * digestSize`.
## - Clears internal buffers after computation.
proc argon2Hex*(
  password, salt: openArray[byte],
  secret: openArray[byte] = @[],
  assocData: openArray[byte] = @[],
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): string =
  var ctx = newArgon2Ctx(
    password, salt, secret, assocData,
    timeCost, memoryCost, parallelism,
    digestSize, version, mode
  )
  let output = ctx.hexDigest()
  ctx.reset()
  return output


## One-shot Argon2 encoded string (bytes API).
## - Returns $argon2{type}$v=..$m=..,t=..,p=..$saltB64$hashB64.
## - Base64 is unpadded to match common encoders.
## - Clears internal buffers after computation.
proc argon2Encoded*(
  password, salt: openArray[byte],
  secret: openArray[byte] = @[],
  assocData: openArray[byte] = @[],
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): string =
  var ctx = newArgon2Ctx(
    password, salt, secret, assocData,
    timeCost, memoryCost, parallelism,
    digestSize, version, mode
  )
  let output = ctx.encoded()
  ctx.reset()
  return output


## One-shot verification against raw expected bytes (bytes API).
## - Recomputes the hash and compares in constant time.
## - Returns true on match; false otherwise.
proc argon2Verify*(
  password, salt: openArray[byte], expected: openArray[byte],
  secret: openArray[byte] = @[],
  assocData: openArray[byte] = @[],
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): bool =
  return ctEqual(
    argon2Hash(password, salt, secret, assocData, timeCost, memoryCost, parallelism, digestSize, version, mode),
    expected
  )


## One-shot verification against an expected lowercase/uppercase hex string (bytes API).
## - Recomputes the hash and compares in constant time (case-insensitive).
proc argon2VerifyHex*(
  password, salt: openArray[byte], expectedHex: string,
  secret: openArray[byte] = @[],
  assocData: openArray[byte] = @[],
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): bool =
  let actual = argon2Hex(password, salt, secret, assocData, timeCost, memoryCost, parallelism, digestSize, version, mode)
  return ctEqualStrings(actual, expectedHex.toLowerAscii())


proc parseModeTag(tag: string): Mode =
  let low = tag.toLowerAscii()
  case low
  of "argon2d": ARGON2D
  of "argon2i": ARGON2I
  of "argon2id": ARGON2ID
  else:
    raise newException(ValueError, "unsupported mode tag: " & tag)


proc parseParamsLine(line: string): tuple[memory: int, time: int, threads: int] =
  var m = -1
  var t = -1
  var p = -1
  for kv in line.split(','):
    let eq = kv.find('=')
    if eq <= 0 or eq >= kv.len.pred:
      continue
    let k = kv[0 .. eq-1].toLowerAscii()
    let v = kv[eq+1 .. kv.high]
    if k == "m": m = parseInt(v)
    elif k == "t": t = parseInt(v)
    elif k == "p": p = parseInt(v)
  if m <= 0 or t <= 0 or p <= 0:
    raise newException(ValueError, "missing or invalid parameters")
  (m, t, p)


## Verify an encoded Argon2 string (bytes API).
## - Parses $argon2{type}$v=..$m=..,t=..,p=..$saltB64$hashB64.
## - Accepts both with/without v= field and unpadded Base64.
## - Returns false on parse errors.
proc argon2VerifyEncoded*(
  password: openArray[byte], encoded: string,
  secret: openArray[byte] = @[],
  assocData: openArray[byte] = @[]
): bool =
  try:
    let parts = encoded.split('$')
    if parts.len < 5:
      return false
    var idx = 1
    let mode = parseModeTag(parts[idx]); inc idx
    var version = Argon2_Version_1_3
    if idx < parts.len and parts[idx].len >= 3 and parts[idx][0..1] == "v=":
      version = parseInt(parts[idx][2 .. parts[idx].high])
      inc idx
    if idx + 2 >= parts.len:
      return false
    let paramsLine = parts[idx]; inc idx
    let saltB64 = parts[idx]; inc idx
    let hashB64 = parts[idx]
    let (memory, time, threads) = parseParamsLine(paramsLine)
    let salt = base64DecodeNoPad(saltB64)
    let expected = base64DecodeNoPad(hashB64)
    if expected.len == 0:
      return false
    let actual = argon2Hash(
      password, salt,
      secret, assocData,
      Positive(time), Positive(memory), Positive(threads), Positive(expected.len),
      Positive(version), mode
    )
    return ctEqual(actual, expected)
  except CatchableError:
    return false


## Verify an encoded Argon2 string (string API).
## - Convenience overload for password as `string`.
proc argon2VerifyEncoded*(
  password: string, encoded: string,
  secret: string = "",
  assocData: string = ""
): bool =
  return argon2VerifyEncoded(
    password.toOpenArrayByte(0, password.len.pred),
    encoded,
    secret.toOpenArrayByte(0, secret.len.pred),
    assocData.toOpenArrayByte(0, assocData.len.pred)
  )


## One-shot Argon2 hashing (string API).
## - Convenience overload accepting string inputs.
## - Returns raw digest bytes.
proc argon2Hash*(
  password, salt: string,
  secret: string = "",
  assocData: string = "",
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): seq[byte] =
  return argon2Hash(
    password.toOpenArrayByte(0, password.len.pred),
    salt.toOpenArrayByte(0, salt.len.pred),
    secret.toOpenArrayByte(0, secret.len.pred),
    assocData.toOpenArrayByte(0, assocData.len.pred),
    timeCost, memoryCost, parallelism, digestSize, version, mode
  )


## One-shot Argon2 hashing to lowercase hex (string API).
## - Convenience overload accepting string inputs.
proc argon2Hex*(
  password, salt: string,
  secret: string = "",
  assocData: string = "",
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): string =
  return argon2Hex(
    password.toOpenArrayByte(0, password.len.pred),
    salt.toOpenArrayByte(0, salt.len.pred),
    secret.toOpenArrayByte(0, secret.len.pred),
    assocData.toOpenArrayByte(0, assocData.len.pred),
    timeCost, memoryCost, parallelism, digestSize, version, mode
  )


## One-shot Argon2 encoded string (string API).
## - Convenience overload accepting string inputs.
proc argon2Encoded*(
  password, salt: string,
  secret: string = "",
  assocData: string = "",
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): string =
  return argon2Encoded(
    password.toOpenArrayByte(0, password.len.pred),
    salt.toOpenArrayByte(0, salt.len.pred),
    secret.toOpenArrayByte(0, secret.len.pred),
    assocData.toOpenArrayByte(0, assocData.len.pred),
    timeCost, memoryCost, parallelism, digestSize, version, mode
  )


## One-shot verification against raw expected bytes (string API).
## - Convenience overload accepting string inputs.
proc argon2Verify*(
  password, salt: string, expected: openArray[byte],
  secret: string = "",
  assocData: string = "",
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): bool =
  return argon2Verify(
    password.toOpenArrayByte(0, password.len.pred),
    salt.toOpenArrayByte(0, salt.len.pred),
    expected,
    secret.toOpenArrayByte(0, secret.len.pred),
    assocData.toOpenArrayByte(0, assocData.len.pred),
    timeCost, memoryCost, parallelism, digestSize, version, mode
  )


## One-shot verification against expected hex (string API).
## - Convenience overload accepting string inputs.
proc argon2VerifyHex*(
  password, salt: string, expectedHex: string,
  secret: string = "",
  assocData: string = "",
  timeCost: Positive = 2,
  memoryCost: Positive = 16,
  parallelism: Positive = 1,
  digestSize: Positive = 32,
  version: Positive = Argon2_Version_1_3,
  mode: Mode = ARGON2ID
): bool =
  return argon2VerifyHex(
    password.toOpenArrayByte(0, password.len.pred),
    salt.toOpenArrayByte(0, salt.len.pred),
    expectedHex,
    secret.toOpenArrayByte(0, secret.len.pred),
    assocData.toOpenArrayByte(0, assocData.len.pred),
    timeCost, memoryCost, parallelism, digestSize, version, mode
  )


when isMainModule:
  echo "=== Argon2 Nim Demo ==="

  block:
    echo "Example 1: derive a hash and encoded string"
    let ctx = newArgon2Ctx(
      "correct horse battery staple",
      "unique-salt",
      timeCost = 3,
      memoryCost = 64,
      parallelism = 2,
      digestSize = 32,
      mode = ARGON2ID
    )
    echo "  Hex digest : ", ctx.hexDigest()
    echo "  Encoded    : ", ctx.encoded()

  block:
    echo "Example 2: verify an encoded hash"
    let stored = argon2Encoded(
      "p@ssw0rd",
      "per-user-salt",
      timeCost = 2,
      memoryCost = 128,
      parallelism = 1,
      digestSize = 32,
      mode = ARGON2ID
    )
    echo "  Stored hash: ", stored
    echo "  Matches correct password? ", argon2VerifyEncoded("p@ssw0rd", stored)
    echo "  Matches wrong password?   ", argon2VerifyEncoded("bad password", stored)
