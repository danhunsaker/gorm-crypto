# gorm-crypto

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
    "crypto/ed25519"
    "crypto/rand"

    "github.com/danhunsaker/gorm-crypto"
    "github.com/danhunsaker/gorm-crypto/encryption"
    "github.com/danhunsaker/gorm-crypto/serializing"
    "github.com/danhunsaker/gorm-crypto/signing"
)

var eKey = "EncryptionKeyThatShouldBe32Bytes"

func main() {
    aes, err := encryption.NewAES256GCM(eKey)
    if err != nil {
        panic(err)
    }

    sKeyPrivate, sKeyPublic, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        panic(err)
    }

    ed25519, err := signing.NewED25519(sKeyPrivate, sKeyPublic)
    if err != nil {
        panic(err)
    }

    gorm_crypto.Init(gorm_crypto.Config{
        Setups: []gorm_crypto.Setup{
            {
                Serializing: serializing.JSON
                Encryption: aes,
                Signing: ed25519,
            },
        }
    })
}
```

With that setup in place, it's as simple as using one or more of the types this library offers to encrypt and/or sign any field you like.

```go
type ContrivedPersonExample struct {
    Name    gorm_crypto.SignedString
    Email   gorm_crypto.EncryptedString
    Address gorm_crypto.NullEncryptedString
    Phone   gorm_crypto.NullSignedEncryptedString
    Age     gorm_crypto.SignedEncryptedUint
}
```

All types have a `Raw` property, which contains the unencrypted raw value - hence the name. Signed types also have a `Valid` property, which tells you whether the value is untampered-with (but only when it's fresh from the DB). Null variants additionally include an `Empty` property, which indicates whether the value is actuall `nil` instead of whatever concrete type it would otherwise be.

## Acknowledgements

As a library with similar goals and implementation, some code is very similar to pkasila/gorm-crypto, which is an older library with more maintainers. If you don't need the advanced features offered here, please use that fine library instead!
