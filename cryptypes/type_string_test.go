package cryptypes_test

import (
	"testing"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

func TestEncryptedString(t *testing.T) {
	expected := cryptypes.EncryptedString{
		Raw: "Test",
	}
	var actual cryptypes.EncryptedString

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

func TestEncryptedStringUnset(t *testing.T) {
	expected := cryptypes.EncryptedString{}
	var actual cryptypes.EncryptedString

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
}

func TestNullEncryptedString(t *testing.T) {
	expected := cryptypes.NullEncryptedString{
		Raw: "Test",
	}
	var actual cryptypes.NullEncryptedString

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

func TestNullEncryptedStringUnset(t *testing.T) {
	expected := cryptypes.NullEncryptedString{}
	var actual cryptypes.NullEncryptedString

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

func TestNullEncryptedStringEmpty(t *testing.T) {
	expected := cryptypes.NullEncryptedString{
		Raw:   "",
		Empty: true,
	}
	var actual cryptypes.NullEncryptedString

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

func TestSignedString(t *testing.T) {
	expected := cryptypes.SignedString{
		Raw: "Test",
	}
	var actual cryptypes.SignedString

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedStringUnset(t *testing.T) {
	expected := cryptypes.SignedString{}
	var actual cryptypes.SignedString

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

func TestSignedStringTampered(t *testing.T) {
	expected := cryptypes.SignedString{
		Raw: "Test",
	}
	var actual cryptypes.SignedString

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue([]byte{})))
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

func TestNullSignedString(t *testing.T) {
	expected := cryptypes.NullSignedString{
		Raw: "Test",
	}
	var actual cryptypes.NullSignedString

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedStringUnset(t *testing.T) {
	expected := cryptypes.NullSignedString{}
	var actual cryptypes.NullSignedString

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

func TestNullSignedStringTampered(t *testing.T) {
	expected := cryptypes.NullSignedString{
		Raw: "Test",
	}
	var actual cryptypes.NullSignedString

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue([]byte{})))
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

func TestNullSignedStringEmpty(t *testing.T) {
	expected := cryptypes.NullSignedString{
		Raw:   "",
		Empty: true,
	}
	var actual cryptypes.NullSignedString

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

func TestSignedEncryptedString(t *testing.T) {
	expected := cryptypes.SignedEncryptedString{
		Raw: "Test",
	}
	var actual cryptypes.SignedEncryptedString

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedEncryptedStringUnset(t *testing.T) {
	expected := cryptypes.SignedEncryptedString{}
	var actual cryptypes.SignedEncryptedString

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

func TestSignedEncryptedStringTampered(t *testing.T) {
	expected := cryptypes.SignedEncryptedString{
		Raw: "Test",
	}
	var actual cryptypes.SignedEncryptedString

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedString{})))
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

func TestNullSignedEncryptedString(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedString{
		Raw: "Test",
	}
	var actual cryptypes.NullSignedEncryptedString

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedStringUnset(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedString{}
	var actual cryptypes.NullSignedEncryptedString

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

func TestNullSignedEncryptedStringTampered(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedString{
		Raw: "Test",
	}
	var actual cryptypes.NullSignedEncryptedString

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedString{})))
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

func TestNullSignedEncryptedStringEmpty(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedString{
		Raw:   "",
		Empty: true,
	}
	var actual cryptypes.NullSignedEncryptedString

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
