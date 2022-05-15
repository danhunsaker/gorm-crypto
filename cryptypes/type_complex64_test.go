package cryptypes_test

import (
	"testing"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

func TestEncryptedComplex64(t *testing.T) {
	expected := cryptypes.EncryptedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.EncryptedComplex64

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

func TestEncryptedComplex64Unset(t *testing.T) {
	expected := cryptypes.EncryptedComplex64{}
	var actual cryptypes.EncryptedComplex64

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw != expected.Raw {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
}

func TestNullEncryptedComplex64(t *testing.T) {
	expected := cryptypes.NullEncryptedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.NullEncryptedComplex64

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

func TestNullEncryptedComplex64Unset(t *testing.T) {
	expected := cryptypes.NullEncryptedComplex64{}
	var actual cryptypes.NullEncryptedComplex64

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

func TestNullEncryptedComplex64Empty(t *testing.T) {
	expected := cryptypes.NullEncryptedComplex64{
		Raw:   42i,
		Empty: true,
	}
	var actual cryptypes.NullEncryptedComplex64

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

func TestSignedComplex64(t *testing.T) {
	expected := cryptypes.SignedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.SignedComplex64

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

func TestSignedComplex64Unset(t *testing.T) {
	expected := cryptypes.SignedComplex64{}
	var actual cryptypes.SignedComplex64

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

func TestSignedComplex64Tampered(t *testing.T) {
	expected := cryptypes.SignedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.SignedComplex64

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawComplexValue(complex64(0))))
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

func TestNullSignedComplex64(t *testing.T) {
	expected := cryptypes.NullSignedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.NullSignedComplex64

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

func TestNullSignedComplex64Unset(t *testing.T) {
	expected := cryptypes.NullSignedComplex64{}
	var actual cryptypes.NullSignedComplex64

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

func TestNullSignedComplex64Tampered(t *testing.T) {
	expected := cryptypes.NullSignedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.NullSignedComplex64

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawComplexValue(complex64(0))))
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

func TestNullSignedComplex64Empty(t *testing.T) {
	expected := cryptypes.NullSignedComplex64{
		Raw:   42i,
		Empty: true,
	}
	var actual cryptypes.NullSignedComplex64

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

func TestSignedEncryptedComplex64(t *testing.T) {
	expected := cryptypes.SignedEncryptedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.SignedEncryptedComplex64

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

func TestSignedEncryptedComplex64Unset(t *testing.T) {
	expected := cryptypes.SignedEncryptedComplex64{}
	var actual cryptypes.SignedEncryptedComplex64

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

func TestSignedEncryptedComplex64Tampered(t *testing.T) {
	expected := cryptypes.SignedEncryptedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.SignedEncryptedComplex64

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedComplex64{})))
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

func TestNullSignedEncryptedComplex64(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.NullSignedEncryptedComplex64

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

func TestNullSignedEncryptedComplex64Unset(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedComplex64{}
	var actual cryptypes.NullSignedEncryptedComplex64

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

func TestNullSignedEncryptedComplex64Tampered(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedComplex64{
		Raw: 42i,
	}
	var actual cryptypes.NullSignedEncryptedComplex64

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedComplex64{})))
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

func TestNullSignedEncryptedComplex64Empty(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedComplex64{
		Raw:   42i,
		Empty: true,
	}
	var actual cryptypes.NullSignedEncryptedComplex64

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
