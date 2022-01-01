package cryptypes_test

import (
	"bytes"
	"testing"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

func TestEncryptedByteSlice(t *testing.T) {
	expected := cryptypes.EncryptedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.EncryptedByteSlice

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
}

func TestNullEncryptedByteSlice(t *testing.T) {
	expected := cryptypes.NullEncryptedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.NullEncryptedByteSlice

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullEncryptedByteSliceEmpty(t *testing.T) {
	expected := cryptypes.NullEncryptedByteSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual cryptypes.NullEncryptedByteSlice

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

func TestSignedByteSlice(t *testing.T) {
	expected := cryptypes.SignedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.SignedByteSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedByteSliceTampered(t *testing.T) {
	expected := cryptypes.SignedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.SignedByteSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue([]byte{})))
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedByteSlice(t *testing.T) {
	expected := cryptypes.NullSignedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.NullSignedByteSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedByteSliceTampered(t *testing.T) {
	expected := cryptypes.NullSignedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.NullSignedByteSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue([]byte{})))
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedByteSliceEmpty(t *testing.T) {
	expected := cryptypes.NullSignedByteSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual cryptypes.NullSignedByteSlice

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

func TestSignedEncryptedByteSlice(t *testing.T) {
	expected := cryptypes.SignedEncryptedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.SignedEncryptedByteSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedEncryptedByteSliceTampered(t *testing.T) {
	expected := cryptypes.SignedEncryptedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.SignedEncryptedByteSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedByteSlice{})))
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedEncryptedByteSlice(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.NullSignedEncryptedByteSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedByteSliceTampered(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedByteSlice{
		Raw: []byte("Test"),
	}
	var actual cryptypes.NullSignedEncryptedByteSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedByteSlice{})))
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedByteSliceEmpty(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedByteSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual cryptypes.NullSignedEncryptedByteSlice

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
