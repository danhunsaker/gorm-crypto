package cryptypes_test

import (
	"reflect"
	"testing"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

func TestEncryptedRuneSlice(t *testing.T) {
	expected := cryptypes.EncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.EncryptedRuneSlice

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
}

func TestNullEncryptedRuneSlice(t *testing.T) {
	expected := cryptypes.NullEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.NullEncryptedRuneSlice

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullEncryptedRuneSliceEmpty(t *testing.T) {
	expected := cryptypes.NullEncryptedRuneSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual cryptypes.NullEncryptedRuneSlice

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

func TestSignedRuneSlice(t *testing.T) {
	expected := cryptypes.SignedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.SignedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedRuneSliceTampered(t *testing.T) {
	expected := cryptypes.SignedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.SignedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue([]rune{})))
	if err != nil {
		t.Error(err)
	}

	if reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedRuneSlice(t *testing.T) {
	expected := cryptypes.NullSignedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.NullSignedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedRuneSliceTampered(t *testing.T) {
	expected := cryptypes.NullSignedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.NullSignedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue([]rune{})))
	if err != nil {
		t.Error(err)
	}

	if reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedRuneSliceEmpty(t *testing.T) {
	expected := cryptypes.NullSignedRuneSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual cryptypes.NullSignedRuneSlice

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

func TestSignedEncryptedRuneSlice(t *testing.T) {
	expected := cryptypes.SignedEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.SignedEncryptedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedEncryptedRuneSliceTampered(t *testing.T) {
	expected := cryptypes.SignedEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.SignedEncryptedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedRuneSlice{})))
	if err != nil {
		t.Error(err)
	}

	if reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedEncryptedRuneSlice(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.NullSignedEncryptedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedRuneSliceTampered(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual cryptypes.NullSignedEncryptedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedRuneSlice{})))
	if err != nil {
		t.Error(err)
	}

	if reflect.DeepEqual(actual.Raw, expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedRuneSliceEmpty(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedRuneSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual cryptypes.NullSignedEncryptedRuneSlice

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
