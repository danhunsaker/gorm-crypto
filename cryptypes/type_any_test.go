package cryptypes_test

import (
	"testing"

	"github.com/danhunsaker/gorm-crypto/cryptypes"
)

var gender = 'X'
var in = testStruct{
	Name:   "Test",
	Age:    42,
	Gender: &gender,
}
var unset testStruct

func TestEncryptedAny(t *testing.T) {
	var out testStruct
	expected := cryptypes.EncryptedAny{
		Raw: &in,
	}
	actual := cryptypes.EncryptedAny{
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

func TestEncryptedAnyUnset(t *testing.T) {
	var out testStruct
	expected := cryptypes.EncryptedAny{
		Raw: &unset,
	}
	actual := cryptypes.EncryptedAny{
		Raw: &out,
	}

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
}

func TestNullEncryptedAny(t *testing.T) {
	var out testStruct
	expected := cryptypes.NullEncryptedAny{
		Raw: &in,
	}
	actual := cryptypes.NullEncryptedAny{
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

func TestNullEncryptedAnyUnset(t *testing.T) {
	var out testStruct
	expected := cryptypes.NullEncryptedAny{
		Raw: &unset,
	}
	actual := cryptypes.NullEncryptedAny{
		Raw: &out,
	}

	err := actual.Scan([]byte(""))
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
	expected := cryptypes.NullEncryptedAny{
		Raw:   &in,
		Empty: true,
	}
	actual := cryptypes.NullEncryptedAny{
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
	expected := cryptypes.SignedAny{
		Raw: &in,
	}
	actual := cryptypes.SignedAny{
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

func TestSignedAnyUnset(t *testing.T) {
	var out testStruct
	expected := cryptypes.SignedAny{
		Raw: &unset,
	}
	actual := cryptypes.SignedAny{
		Raw: &out,
	}

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestSignedAnyTampered(t *testing.T) {
	var out testStruct
	expected := cryptypes.SignedAny{
		Raw: &in,
	}
	actual := cryptypes.SignedAny{
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
	expected := cryptypes.NullSignedAny{
		Raw: &in,
	}
	actual := cryptypes.NullSignedAny{
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

func TestNullSignedAnyUnset(t *testing.T) {
	var out testStruct
	expected := cryptypes.NullSignedAny{
		Raw: &unset,
	}
	actual := cryptypes.NullSignedAny{
		Raw: &out,
	}

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedAnyTampered(t *testing.T) {
	var out testStruct
	expected := cryptypes.NullSignedAny{
		Raw: &in,
	}
	actual := cryptypes.NullSignedAny{
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
	expected := cryptypes.NullSignedAny{
		Raw:   &in,
		Empty: true,
	}
	actual := cryptypes.NullSignedAny{
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
	expected := cryptypes.SignedEncryptedAny{
		Raw: &in,
	}
	actual := cryptypes.SignedEncryptedAny{
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

func TestSignedEncryptedAnyUnset(t *testing.T) {
	var out testStruct
	expected := cryptypes.SignedEncryptedAny{
		Raw: &unset,
	}
	actual := cryptypes.SignedEncryptedAny{
		Raw: &out,
	}

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
}

func TestSignedEncryptedAnyTampered(t *testing.T) {
	var out testStruct
	expected := cryptypes.SignedEncryptedAny{
		Raw: &in,
	}
	actual := cryptypes.SignedEncryptedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedAny{Raw: testStruct{}})))
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
	expected := cryptypes.NullSignedEncryptedAny{
		Raw: &in,
	}
	actual := cryptypes.NullSignedEncryptedAny{
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

func TestNullSignedEncryptedAnyUnset(t *testing.T) {
	var out testStruct
	expected := cryptypes.NullSignedEncryptedAny{
		Raw: &unset,
	}
	actual := cryptypes.NullSignedEncryptedAny{
		Raw: &out,
	}

	err := actual.Scan([]byte(""))
	if err != nil {
		t.Error(err)
	}

	if !actual.Raw.(*testStruct).Equals(*expected.Raw.(*testStruct)) {
		t.Errorf("Expected raw = %v; got %v", *expected.Raw.(*testStruct), *actual.Raw.(*testStruct))
	}
	if actual.Valid != false {
		t.Errorf("Expected valid = false; got %v", actual.Valid)
	}
	if actual.Empty != expected.Empty {
		t.Errorf("Expected empty = %v; got %v", expected.Empty, actual.Empty)
	}
}

func TestNullSignedEncryptedAnyTampered(t *testing.T) {
	var out testStruct
	expected := cryptypes.NullSignedEncryptedAny{
		Raw: &in,
	}
	actual := cryptypes.NullSignedEncryptedAny{
		Raw: &out,
	}

	signed, err := expected.Value()
	if err != nil {
		t.Error(err)
	}
	err = actual.Scan(tamperWith(signed, unwrapValue(cryptypes.EncryptedAny{Raw: testStruct{}})))
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
	expected := cryptypes.NullSignedEncryptedAny{
		Raw:   &in,
		Empty: true,
	}
	actual := cryptypes.NullSignedEncryptedAny{
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
