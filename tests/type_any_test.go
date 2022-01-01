package gormcrypto_test

import (
	"testing"

	gc "github.com/danhunsaker/gorm-crypto"
)

var gender = 'X'
var in = testStruct{
	Name:   "Test",
	Age:    42,
	Gender: &gender,
}

func TestEncryptedAny(t *testing.T) {
	var out testStruct
	expected := gc.EncryptedAny{
		Raw: &in,
	}
	actual := gc.EncryptedAny{
		Raw: &out,
	}

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
}

func TestNullEncryptedAny(t *testing.T) {
	var out testStruct
	expected := gc.NullEncryptedAny{
		Raw: &in,
	}
	actual := gc.NullEncryptedAny{
		Raw: &out,
	}

	crypted, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(crypted)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullEncryptedAnyEmpty(t *testing.T) {
	var out testStruct
	expected := gc.NullEncryptedAny{
		Raw:   &in,
		Empty: true,
	}
	actual := gc.NullEncryptedAny{
		Raw: &out,
	}

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

func TestSignedAny(t *testing.T) {
	var out testStruct
	expected := gc.SignedAny{
		Raw: &in,
	}
	actual := gc.SignedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedAnyTampered(t *testing.T) {
	var out testStruct
	expected := gc.SignedAny{
		Raw: &in,
	}
	actual := gc.SignedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue(testStruct{})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw != %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedAny(t *testing.T) {
	var out testStruct
	expected := gc.NullSignedAny{
		Raw: &in,
	}
	actual := gc.NullSignedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedAnyTampered(t *testing.T) {
	var out testStruct
	expected := gc.NullSignedAny{
		Raw: &in,
	}
	actual := gc.NullSignedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, rawValue(testStruct{})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw != %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedAnyEmpty(t *testing.T) {
	var out testStruct
	expected := gc.NullSignedAny{
		Raw:   &in,
		Empty: true,
	}
	actual := gc.NullSignedAny{
		Raw: &out,
	}

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

func TestSignedEncryptedAny(t *testing.T) {
	var out testStruct
	expected := gc.SignedEncryptedAny{
		Raw: &in,
	}
	actual := gc.SignedEncryptedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
}

func TestSignedEncryptedAnyTampered(t *testing.T) {
	var out testStruct
	expected := gc.SignedEncryptedAny{
		Raw: &in,
	}
	actual := gc.SignedEncryptedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(gc.EncryptedAny{Raw: testStruct{}})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw != %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestNullSignedEncryptedAny(t *testing.T) {
	var out testStruct
	expected := gc.NullSignedEncryptedAny{
		Raw: &in,
	}
	actual := gc.NullSignedEncryptedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(signed)
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != true {
		t.Errorf("Expected valid = true; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedAnyTampered(t *testing.T) {
	var out testStruct
	expected := gc.NullSignedEncryptedAny{
		Raw: &in,
	}
	actual := gc.NullSignedEncryptedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(gc.EncryptedAny{Raw: testStruct{}})))
	if err != nil {
		t.Error(err)
	}

	if actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw != %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedAnyEmpty(t *testing.T) {
	var out testStruct
	expected := gc.NullSignedEncryptedAny{
		Raw:   &in,
		Empty: true,
	}
	actual := gc.NullSignedEncryptedAny{
		Raw: &out,
	}

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
