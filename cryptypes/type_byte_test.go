package cryptypes_test

import (
	"testing"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

func TestEncryptedByte(t *testing.T) {
	expected := cryptypes.EncryptedByte{
		Raw: 42,
	}
	var actual cryptypes.EncryptedByte

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

func TestNullEncryptedByte(t *testing.T) {
	expected := cryptypes.NullEncryptedByte{
		Raw: 42,
	}
	var actual cryptypes.NullEncryptedByte

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

func TestNullEncryptedByteEmpty(t *testing.T) {
	expected := cryptypes.NullEncryptedByte{
		Raw:   42,
		Empty: true,
	}
	var actual cryptypes.NullEncryptedByte

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

func TestSignedByte(t *testing.T) {
	expected := cryptypes.SignedByte{
		Raw: 42,
	}
	var actual cryptypes.SignedByte

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

func TestSignedByteTampered(t *testing.T) {
	expected := cryptypes.SignedByte{
		Raw: 42,
	}
	var actual cryptypes.SignedByte

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue(0)))
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

func TestNullSignedByte(t *testing.T) {
	expected := cryptypes.NullSignedByte{
		Raw: 42,
	}
	var actual cryptypes.NullSignedByte

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

func TestNullSignedByteTampered(t *testing.T) {
	expected := cryptypes.NullSignedByte{
		Raw: 42,
	}
	var actual cryptypes.NullSignedByte

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue(0)))
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

func TestNullSignedByteEmpty(t *testing.T) {
	expected := cryptypes.NullSignedByte{
		Raw:   42,
		Empty: true,
	}
	var actual cryptypes.NullSignedByte

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

func TestSignedEncryptedByte(t *testing.T) {
	expected := cryptypes.SignedEncryptedByte{
		Raw: 42,
	}
	var actual cryptypes.SignedEncryptedByte

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

func TestSignedEncryptedByteTampered(t *testing.T) {
	expected := cryptypes.SignedEncryptedByte{
		Raw: 42,
	}
	var actual cryptypes.SignedEncryptedByte

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedByte{})))
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

func TestNullSignedEncryptedByte(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedByte{
		Raw: 42,
	}
	var actual cryptypes.NullSignedEncryptedByte

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

func TestNullSignedEncryptedByteTampered(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedByte{
		Raw: 42,
	}
	var actual cryptypes.NullSignedEncryptedByte

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedByte{})))
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

func TestNullSignedEncryptedByteEmpty(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedByte{
		Raw:   42,
		Empty: true,
	}
	var actual cryptypes.NullSignedEncryptedByte

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
