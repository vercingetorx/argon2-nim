import ../argon2_core

# NOTE: https://cs.opensource.google/go/x/crypto/+/master:argon2/argon2_test.go

const
  genKatPassword* = [
      0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte,
      0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte,
      0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte,
      0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte, 0x01.byte
    ]
  genKatSalt*   = [0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte, 0x02.byte]
  genKatSecret* = [0x03.byte, 0x03.byte, 0x03.byte, 0x03.byte, 0x03.byte, 0x03.byte, 0x03.byte, 0x03.byte]
  genKatAAD*    = [0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte, 0x04.byte]

  testVectors*: array[24, tuple[
      mode:        Mode,
      time:        int,
      memory:      int,
      threads:     int,
      hash:        string
    ]
  ] = [
    (
      mode: ARGON2I, time: 1, memory: 64, threads: 1,
      hash: "b9c401d1844a67d50eae3967dc28870b22e508092e861a37"
    ),
    (
      mode: ARGON2D, time: 1, memory: 64, threads: 1,
      hash: "8727405fd07c32c78d64f547f24150d3f2e703a89f981a19"
    ),
    (
      mode: ARGON2ID, time: 1, memory: 64, threads: 1,
      hash: "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"
    ),
    (
      mode: ARGON2I, time: 2, memory: 64, threads: 1,
      hash: "8cf3d8f76a6617afe35fac48eb0b7433a9a670ca4a07ed64"
    ),
    (
      mode: ARGON2D, time: 2, memory: 64, threads: 1,
      hash: "3be9ec79a69b75d3752acb59a1fbb8b295a46529c48fbb75"
    ),
    (
      mode: ARGON2ID, time: 2, memory: 64, threads: 1,
      hash: "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"
    ),
    (
      mode: ARGON2I, time: 2, memory: 64, threads: 2,
      hash: "2089f3e78a799720f80af806553128f29b132cafe40d059f"
    ),
    (
      mode: ARGON2D, time: 2, memory: 64, threads: 2,
      hash: "68e2462c98b8bc6bb60ec68db418ae2c9ed24fc6748a40e9"
    ),
    (
      mode: ARGON2ID, time: 2, memory: 64, threads: 2,
      hash: "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"
    ),
    (
      mode: ARGON2I, time: 3, memory: 256, threads: 2,
      hash: "f5bbf5d4c3836af13193053155b73ec7476a6a2eb93fd5e6"
    ),
    (
      mode: ARGON2D, time: 3, memory: 256, threads: 2,
      hash: "f4f0669218eaf3641f39cc97efb915721102f4b128211ef2"
    ),
    (
      mode: ARGON2ID, time: 3, memory: 256, threads: 2,
      hash: "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b"
    ),
    (
      mode: ARGON2I, time: 4, memory: 4096, threads: 4,
      hash: "a11f7b7f3f93f02ad4bddb59ab62d121e278369288a0d0e7"
    ),
    (
      mode: ARGON2D, time: 4, memory: 4096, threads: 4,
      hash: "935598181aa8dc2b720914aa6435ac8d3e3a4210c5b0fb2d"
    ),
    (
      mode: ARGON2ID, time: 4, memory: 4096, threads: 4,
      hash: "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a"
    ),
    (
      mode: ARGON2I, time: 4, memory: 1024, threads: 8,
      hash: "0cdd3956aa35e6b475a7b0c63488822f774f15b43f6e6e17"
    ),
    (
      mode: ARGON2D, time: 4, memory: 1024, threads: 8,
      hash: "83604fc2ad0589b9d055578f4d3cc55bc616df3578a896e9"
    ),
    (
      mode: ARGON2ID, time: 4, memory: 1024, threads: 8,
      hash: "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f"
    ),
    (
      mode: ARGON2I, time: 2, memory: 64, threads: 3,
      hash: "5cab452fe6b8479c8661def8cd703b611a3905a6d5477fe6"
    ),
    (
      mode: ARGON2D, time: 2, memory: 64, threads: 3,
      hash: "22474a423bda2ccd36ec9afd5119e5c8949798cadf659f51"
    ),
    (
      mode: ARGON2ID, time: 2, memory: 64, threads: 3,
      hash: "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079"
    ),
    (
      mode: ARGON2I, time: 3, memory: 1024, threads: 6,
      hash: "d236b29c2b2a09babee842b0dec6aa1e83ccbdea8023dced"
    ),
    (
      mode: ARGON2D, time: 3, memory: 1024, threads: 6,
      hash: "a3351b0319a53229152023d9206902f4ef59661cdca89481"
    ),
    (
      mode: ARGON2ID, time: 3, memory: 1024, threads: 6,
      hash: "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016"
    )
  ]
