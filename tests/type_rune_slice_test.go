package gc_test

import (
	"reflect"
	"testing"

	gc "github.com/danhunsaker/gorm-crypto"
)

func TestEncryptedRuneSlice(t *testing.T) {
	expected := gc.EncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.EncryptedRuneSlice

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
	expected := gc.NullEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.NullEncryptedRuneSlice

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
	expected := gc.NullEncryptedRuneSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual gc.NullEncryptedRuneSlice

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
	expected := gc.SignedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.SignedRuneSlice

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
	expected := gc.SignedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.SignedRuneSlice

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
	expected := gc.NullSignedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.NullSignedRuneSlice

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
	expected := gc.NullSignedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.NullSignedRuneSlice

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
	expected := gc.NullSignedRuneSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual gc.NullSignedRuneSlice

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
	expected := gc.SignedEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.SignedEncryptedRuneSlice

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
	expected := gc.SignedEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.SignedEncryptedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, suppressError(gc.EncryptedRuneSlice{}.Value())))
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
	expected := gc.NullSignedEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.NullSignedEncryptedRuneSlice

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
	expected := gc.NullSignedEncryptedRuneSlice{
		Raw: []rune("Test"),
	}
	var actual gc.NullSignedEncryptedRuneSlice

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, suppressError(gc.EncryptedRuneSlice{}.Value())))
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
	expected := gc.NullSignedEncryptedRuneSlice{
		Raw:   nil,
		Empty: true,
	}
	var actual gc.NullSignedEncryptedRuneSlice

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
