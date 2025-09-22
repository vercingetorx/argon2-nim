import std/unittest

import ../argon2
import kats

const
    testPassword = "password"
    testSalt = "somesalt"


suite "Argon2 Known-Answer Tests":
  for i, tv in testVectors:
    test "KAT #" & $i & " (" & $tv.mode & ") t=" & $tv.time & " m=" & $tv.memory & " p=" & $tv.threads:
      let hex = argon2Hex(
        testPassword,
        testSalt,
        timeCost = tv.time,
        memoryCost = tv.memory,
        parallelism = tv.threads,
        digestSize = 24,
        mode = tv.mode
      )
      check hex == tv.hash

