package cryptypes_test

import (
	"testing"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

func TestEncryptedBool(t *testing.T) {
	expected := cryptypes.EncryptedBool{
		Raw: true,
	}
	var actual cryptypes.EncryptedBool

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
}

func TestEncryptedBoolUnset(t *testing.T) {
	expected := cryptypes.EncryptedBool{}
	var actual cryptypes.EncryptedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
}

func TestNullEncryptedBool(t *testing.T) {
	expected := cryptypes.NullEncryptedBool{
		Raw: true,
	}
	var actual cryptypes.NullEncryptedBool

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullEncryptedBoolUnset(t *testing.T) {
	expected := cryptypes.NullEncryptedBool{}
	var actual cryptypes.NullEncryptedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullEncryptedBoolEmpty(t *testing.T) {
	expected := cryptypes.NullEncryptedBool{
		Raw:   true,
		Empty: true,
	}
	var actual cryptypes.NullEncryptedBool

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestSignedBool(t *testing.T) {
	expected := cryptypes.SignedBool{}
	var actual cryptypes.SignedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestSignedBoolUnset(t *testing.T) {
	expected := cryptypes.SignedBool{}
	var actual cryptypes.SignedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestSignedBoolTampered(t *testing.T) {
	expected := cryptypes.SignedBool{
		Raw: true,
	}
	var actual cryptypes.SignedBool

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue(false)))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw == expected.Raw {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedBool(t *testing.T) {
	expected := cryptypes.NullSignedBool{}
	var actual cryptypes.NullSignedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedBoolUnset(t *testing.T) {
	expected := cryptypes.NullSignedBool{}
	var actual cryptypes.NullSignedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedBoolTampered(t *testing.T) {
	expected := cryptypes.NullSignedBool{
		Raw: true,
	}
	var actual cryptypes.NullSignedBool

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue(false)))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw == expected.Raw {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedBoolEmpty(t *testing.T) {
	expected := cryptypes.NullSignedBool{
		Raw:   true,
		Empty: true,
	}
	var actual cryptypes.NullSignedBool

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestSignedEncryptedBool(t *testing.T) {
	expected := cryptypes.SignedEncryptedBool{}
	var actual cryptypes.SignedEncryptedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestSignedEncryptedBoolUnset(t *testing.T) {
	expected := cryptypes.SignedEncryptedBool{}
	var actual cryptypes.SignedEncryptedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestSignedEncryptedBoolTampered(t *testing.T) {
	expected := cryptypes.SignedEncryptedBool{
		Raw: true,
	}
	var actual cryptypes.SignedEncryptedBool

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedBool{})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw == expected.Raw {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedEncryptedBool(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedBool{}
	var actual cryptypes.NullSignedEncryptedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedBoolUnset(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedBool{}
	var actual cryptypes.NullSignedEncryptedBool

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedBoolTampered(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedBool{
		Raw: true,
	}
	var actual cryptypes.NullSignedEncryptedBool

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedBool{})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw == expected.Raw {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedBoolEmpty(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedBool{
		Raw:   true,
		Empty: true,
	}
	var actual cryptypes.NullSignedEncryptedBool

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}
