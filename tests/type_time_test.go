package gormcrypto_test

import (
	"testing"
	"time"

	gc "github.com/danhunsaker/gorm-crypto"
)

func TestEncryptedTime(t *testing.T) {
	expected := gc.EncryptedTime{
		Raw: time.Now(),
	}
	var actual gc.EncryptedTime

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

func TestNullEncryptedTime(t *testing.T) {
	expected := gc.NullEncryptedTime{
		Raw: time.Now(),
	}
	var actual gc.NullEncryptedTime

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

func TestNullEncryptedTimeEmpty(t *testing.T) {
	expected := gc.NullEncryptedTime{
		Raw:   time.Now(),
		Empty: true,
	}
	var actual gc.NullEncryptedTime

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
	expected := gc.SignedTime{
		Raw: time.Now(),
	}
	var actual gc.SignedTime

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

func TestSignedTimeTampered(t *testing.T) {
	expected := gc.SignedTime{
		Raw: time.Now(),
	}
	var actual gc.SignedTime

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
	expected := gc.NullSignedTime{
		Raw: time.Now(),
	}
	var actual gc.NullSignedTime

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

func TestNullSignedTimeTampered(t *testing.T) {
	expected := gc.NullSignedTime{
		Raw: time.Now(),
	}
	var actual gc.NullSignedTime

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
	expected := gc.NullSignedTime{
		Raw:   time.Now(),
		Empty: true,
	}
	var actual gc.NullSignedTime

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
	expected := gc.SignedEncryptedTime{
		Raw: time.Now(),
	}
	var actual gc.SignedEncryptedTime

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

func TestSignedEncryptedTimeTampered(t *testing.T) {
	expected := gc.SignedEncryptedTime{
		Raw: time.Now(),
	}
	var actual gc.SignedEncryptedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(gc.EncryptedTime{})))
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
	expected := gc.NullSignedEncryptedTime{
		Raw: time.Now(),
	}
	var actual gc.NullSignedEncryptedTime

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

func TestNullSignedEncryptedTimeTampered(t *testing.T) {
	expected := gc.NullSignedEncryptedTime{
		Raw: time.Now(),
	}
	var actual gc.NullSignedEncryptedTime

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(gc.EncryptedTime{})))
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
	expected := gc.NullSignedEncryptedTime{
		Raw:   time.Now(),
		Empty: true,
	}
	var actual gc.NullSignedEncryptedTime

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
