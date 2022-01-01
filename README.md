# gormcrypto

![GitHub license](https://img.shields.io/github/license/danhunsaker/gorm-crypto)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/danhunsaker/gorm-crypto)
![GitHub Sponsors](https://img.shields.io/github/sponsors/danhunsaker)
![Liberapay patrons](https://img.shields.io/liberapay/patrons/danhunsaker)

![GitHub commits since latest release (by SemVer)](https://img.shields.io/github/commits-since/danhunsaker/gorm-crypto/latest?sort=semver)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/danhunsaker/gorm-crypto/CI)
[![Go Report Card](https://goreportcard.com/badge/github.com/danhunsaker/gorm-crypto)](https://goreportcard.com/report/github.com/danhunsaker/gorm-crypto)
![Scrutinizer coverage](https://img.shields.io/scrutinizer/coverage/g/danhunsaker/gorm-crypto)
![Scrutinizer code quality](https://img.shields.io/scrutinizer/quality/g/danhunsaker/gorm-crypto)

Another library for encrypting/signing data with GORM

## Usage

As with any other Go lib, you'll want to `go get` the module:

```bash
go get github.com/danhunsaker/gorm-crypto
```

Then, in your code, you would do something like this:

```go
package main

import (
    "time"

    gc "github.com/danhunsaker/gorm-crypto"
    "github.com/danhunsaker/gorm-crypto/encoding"
    "github.com/danhunsaker/gorm-crypto/encryption"
    "github.com/danhunsaker/gorm-crypto/serializing"
    "github.com/danhunsaker/gorm-crypto/signing"
)

var eKey = "EncryptionKeyThatShouldBe32Bytes"
var sKey = "SigningKeyThatShouldBe32BytesToo"

func main() {
    aes, err := encryption.NewAES256GCM(eKey)
    if err != nil {
        panic(err)
    }

    gc.Init(gc.Config{
        Setups: map[time.Time]gc.Setup{
            time.Date(2022, 1, 1, 15, 17, 35, 0, time.UTC): {
				Encoder:          encoding.Base64{},
				Serializer:       serializing.JSON{},
				EncryptAlgorithm: aes,
				SignAlgorithm:    signing.NewED25519FromSeed(sKey),
            },
        },
    })
}
```

With that setup in place, it's as simple as using one or more of the types this library offers to encrypt and/or sign any field you like.

```go
import "github.com/danhunsaker/gorm-crypto/cryptypes"

type ContrivedPersonExample struct {
    Name    cryptypes.SignedString
    Email   cryptypes.EncryptedString
    Address cryptypes.NullEncryptedString
    Phone   cryptypes.NullSignedEncryptedString
    Age     cryptypes.SignedEncryptedUint
}
```

All types have a `Raw` property, which contains the unencrypted raw value - hence the name. Signed types also have a `Valid` property, which tells you
whether the value is untampered-with (but only when it's fresh from the DB). Null variants additionally include an `Empty` property, which indicates
whether the value is actually `nil` instead of whatever concrete type it would otherwise be.

## Acknowledgements

As a library with similar goals and implementation, some code is very similar to
[github.com/pkasila/gorm-crypto](https://pkg.go.dev/github.com/pkasila/gorm-crypto), which is an older library with more maintainers. If you don't
need the advanced features offered here, please use that fine library instead!
