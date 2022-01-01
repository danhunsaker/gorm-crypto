package cryptypes_test

import (
	"testing"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

func TestEncryptedUint16(t *testing.T) {
	expected := cryptypes.EncryptedUint16{
		Raw: 42,
	}
	var actual cryptypes.EncryptedUint16

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

func TestNullEncryptedUint16(t *testing.T) {
	expected := cryptypes.NullEncryptedUint16{
		Raw: 42,
	}
	var actual cryptypes.NullEncryptedUint16

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

func TestNullEncryptedUint16Empty(t *testing.T) {
	expected := cryptypes.NullEncryptedUint16{
		Raw:   42,
		Empty: true,
	}
	var actual cryptypes.NullEncryptedUint16

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

func TestSignedUint16(t *testing.T) {
	expected := cryptypes.SignedUint16{
		Raw: 42,
	}
	var actual cryptypes.SignedUint16

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

func TestSignedUint16Tampered(t *testing.T) {
	expected := cryptypes.SignedUint16{
		Raw: 42,
	}
	var actual cryptypes.SignedUint16

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

func TestNullSignedUint16(t *testing.T) {
	expected := cryptypes.NullSignedUint16{
		Raw: 42,
	}
	var actual cryptypes.NullSignedUint16

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

func TestNullSignedUint16Tampered(t *testing.T) {
	expected := cryptypes.NullSignedUint16{
		Raw: 42,
	}
	var actual cryptypes.NullSignedUint16

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

func TestNullSignedUint16Empty(t *testing.T) {
	expected := cryptypes.NullSignedUint16{
		Raw:   42,
		Empty: true,
	}
	var actual cryptypes.NullSignedUint16

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

func TestSignedEncryptedUint16(t *testing.T) {
	expected := cryptypes.SignedEncryptedUint16{
		Raw: 42,
	}
	var actual cryptypes.SignedEncryptedUint16

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

func TestSignedEncryptedUint16Tampered(t *testing.T) {
	expected := cryptypes.SignedEncryptedUint16{
		Raw: 42,
	}
	var actual cryptypes.SignedEncryptedUint16

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedUint16{})))
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

func TestNullSignedEncryptedUint16(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedUint16{
		Raw: 42,
	}
	var actual cryptypes.NullSignedEncryptedUint16

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

func TestNullSignedEncryptedUint16Tampered(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedUint16{
		Raw: 42,
	}
	var actual cryptypes.NullSignedEncryptedUint16

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedUint16{})))
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

func TestNullSignedEncryptedUint16Empty(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedUint16{
		Raw:   42,
		Empty: true,
	}
	var actual cryptypes.NullSignedEncryptedUint16

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
