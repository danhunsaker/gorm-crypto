package cryptypes_test

import (
	"testing"
	"time"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

func TestEncryptedTime(t *testing.T) {
	expected := cryptypes.EncryptedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.EncryptedTime

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
}

func TestEncryptedTimeUnset(t *testing.T) {
	expected := cryptypes.EncryptedTime{}
	var actual cryptypes.EncryptedTime

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
}

func TestNullEncryptedTime(t *testing.T) {
	expected := cryptypes.NullEncryptedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.NullEncryptedTime

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullEncryptedTimeUnset(t *testing.T) {
	expected := cryptypes.NullEncryptedTime{}
	var actual cryptypes.NullEncryptedTime

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullEncryptedTimeEmpty(t *testing.T) {
	expected := cryptypes.NullEncryptedTime{
		Raw:   time.Now(),
		Empty: true,
	}
	var actual cryptypes.NullEncryptedTime

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

func TestSignedTime(t *testing.T) {
	expected := cryptypes.SignedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.SignedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedTimeUnset(t *testing.T) {
	expected := cryptypes.SignedTime{}
	var actual cryptypes.SignedTime

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestSignedTimeTampered(t *testing.T) {
	expected := cryptypes.SignedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.SignedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue(time.Time{})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedTime(t *testing.T) {
	expected := cryptypes.NullSignedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.NullSignedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedTimeUnset(t *testing.T) {
	expected := cryptypes.NullSignedTime{}
	var actual cryptypes.NullSignedTime

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedTimeTampered(t *testing.T) {
	expected := cryptypes.NullSignedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.NullSignedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue(time.Time{})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedTimeEmpty(t *testing.T) {
	expected := cryptypes.NullSignedTime{
		Raw:   time.Now(),
		Empty: true,
	}
	var actual cryptypes.NullSignedTime

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

func TestSignedEncryptedTime(t *testing.T) {
	expected := cryptypes.SignedEncryptedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.SignedEncryptedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedEncryptedTimeUnset(t *testing.T) {
	expected := cryptypes.SignedEncryptedTime{}
	var actual cryptypes.SignedEncryptedTime

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestSignedEncryptedTimeTampered(t *testing.T) {
	expected := cryptypes.SignedEncryptedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.SignedEncryptedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedTime{})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedEncryptedTime(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.NullSignedEncryptedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedTimeUnset(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedTime{}
	var actual cryptypes.NullSignedEncryptedTime

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw = %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedTimeTampered(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedTime{
		Raw: time.Now(),
	}
	var actual cryptypes.NullSignedEncryptedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedTime{})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw.Equal(expected.Raw) {
		t.Errorf("Expected raw != %v; got %v", expected.Raw, actual.Raw)
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedTimeEmpty(t *testing.T) {
	expected := cryptypes.NullSignedEncryptedTime{
		Raw:   time.Now(),
		Empty: true,
	}
	var actual cryptypes.NullSignedEncryptedTime

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
