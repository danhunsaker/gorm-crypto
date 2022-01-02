package serializing_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/danhunsaker/gorm-crypto/serializing"
)

func TestSerializing(t *testing.T) {
	for _, serializer := range []serializing.Algorithm{
		serializing.GOB{},
		serializing.JSON{},
	} {
		var actualBool bool
		var actualByteSlice []byte
		var actualByte byte
		var actualComplex64 complex64
		var actualComplex128 complex128
		var actualFloat32 float32
		var actualFloat64 float64
		var actualInt int
		var actualInt8 int8
		var actualInt16 int16
		var actualInt32 int32
		var actualInt64 int64
		var actualRuneSlice []rune
		var actualRune rune
		var actualString string
		var actualTime time.Time
		var actualUint uint
		var actualUint8 uint8
		var actualUint16 uint16
		var actualUint32 uint32
		var actualUint64 uint64
		var actualStruct testStruct

		var expectedBool bool = true
		var expectedByteSlice []byte = []byte("Test")
		var expectedByte byte = 255
		var expectedComplex64 complex64 = 3.141529 + 42i
		var expectedComplex128 complex128 = 3.141529 + 42i
		var expectedFloat32 float32 = 3.141529
		var expectedFloat64 float64 = 3.141529
		var expectedInt int = -42
		var expectedInt8 int8 = -42
		var expectedInt16 int16 = -42
		var expectedInt32 int32 = -42
		var expectedInt64 int64 = -42
		var expectedRuneSlice []rune = []rune{'T', 'e', 's', 't'}
		var expectedRune rune = 'X'
		var expectedString string = "test"
		var expectedTime time.Time = time.Unix(time.Now().Unix(), int64(time.Now().Nanosecond()))
		var expectedUint uint = 42
		var expectedUint8 uint8 = 42
		var expectedUint16 uint16 = 42
		var expectedUint32 uint32 = 42
		var expectedUint64 uint64 = 42
		var expectedStruct testStruct = testStruct{
			Bool:      expectedBool,
			ByteSlice: expectedByteSlice,
			Float:     expectedFloat64,
			Int:       expectedInt64,
			Rune:      expectedRune,
			RuneSlice: expectedRuneSlice,
			String:    expectedString,
			Time:      expectedTime,
			Uint:      expectedUint64,
		}

		runTest(t, serializer, expectedBool, actualBool)
		runTest(t, serializer, expectedByteSlice, actualByteSlice)
		runTest(t, serializer, expectedByte, actualByte)
		runTest(t, serializer, expectedComplex64, actualComplex64)
		runTest(t, serializer, expectedComplex128, actualComplex128)
		runTest(t, serializer, expectedFloat32, actualFloat32)
		runTest(t, serializer, expectedFloat64, actualFloat64)
		runTest(t, serializer, expectedInt, actualInt)
		runTest(t, serializer, expectedInt8, actualInt8)
		runTest(t, serializer, expectedInt16, actualInt16)
		runTest(t, serializer, expectedInt32, actualInt32)
		runTest(t, serializer, expectedInt64, actualInt64)
		runTest(t, serializer, expectedRuneSlice, actualRuneSlice)
		runTest(t, serializer, expectedRune, actualRune)
		runTest(t, serializer, expectedString, actualString)
		runTest(t, serializer, expectedTime, actualTime)
		runTest(t, serializer, expectedUint, actualUint)
		runTest(t, serializer, expectedUint8, actualUint8)
		runTest(t, serializer, expectedUint16, actualUint16)
		runTest(t, serializer, expectedUint32, actualUint32)
		runTest(t, serializer, expectedUint64, actualUint64)
		runTest(t, serializer, expectedStruct, actualStruct)
	}
}

func runTest(t *testing.T, serializer serializing.Algorithm, expected, target interface{}) {
	t.Run(fmt.Sprintf("%s(%s)", reflect.TypeOf(serializer).String(), reflect.TypeOf(expected).String()), func(t *testing.T) {
		serialized, err := serialize(serializer, expected)
		if err != nil {
			t.Errorf("%s.Serialize error: %v", reflect.TypeOf(serializer).String(), err)
		}

		actual, err := unserialize(serializer, serialized, target)
		if err != nil {
			t.Errorf("%s.Unserialize error: %v", reflect.TypeOf(serializer).String(), err)
		}

		var equal bool
		switch actual := actual.(type) {
		case []rune:
			equal = reflect.DeepEqual(actual, expected)
		case []byte:
			equal = bytes.Equal(actual, expected.([]byte))
		case time.Time:
			equal = actual.Equal(expected.(time.Time))
		case testStruct:
			equal = actual.Equal(expected.(testStruct))
		default:
			equal = (actual == expected)
		}

		if !equal {
			t.Errorf("Expected %s(%v); got %s(%v) instead", reflect.TypeOf(expected).String(), expected, reflect.TypeOf(actual).String(), actual)
		}
	})
}

func serialize(serializer serializing.Algorithm, expected interface{}) (serialized []byte, err error) {
	switch expected := expected.(type) {
	case bool:
		serialized, err = serializer.Serialize(expected)
	case []byte:
		serialized, err = serializer.Serialize(expected)
	case []rune:
		serialized, err = serializer.Serialize(expected)
	case string:
		serialized, err = serializer.Serialize(expected)
	case testStruct:
		serialized, err = serializer.Serialize(expected)
	case complex64, complex128, float32, float64, time.Time:
		serialized, err = serializeNumeric(serializer, expected)
	case int, int8, int16, int32, int64:
		serialized, err = serializeInt(serializer, expected)
	case uint, uint8, uint16, uint32, uint64:
		serialized, err = serializeUint(serializer, expected)
	default:
		err = fmt.Errorf("unsupported value %s(%v)", reflect.TypeOf(expected).String(), expected)
	}

	return
}

func serializeNumeric(serializer serializing.Algorithm, expected interface{}) (serialized []byte, err error) {
	switch expected := expected.(type) {
	case complex64:
		var bin bytes.Buffer
		err = binary.Write(&bin, binary.LittleEndian, expected)
		if err == nil {
			serialized, err = serializer.Serialize(bin.Bytes())
		}
	case complex128:
		var bin bytes.Buffer
		err = binary.Write(&bin, binary.LittleEndian, expected)
		if err == nil {
			serialized, err = serializer.Serialize(bin.Bytes())
		}
	case float32:
		serialized, err = serializer.Serialize(expected)
	case float64:
		serialized, err = serializer.Serialize(expected)
	case time.Time:
		serialized, err = serializer.Serialize(expected)
	}

	return
}

func serializeInt(serializer serializing.Algorithm, expected interface{}) (serialized []byte, err error) {
	switch expected := expected.(type) {
	case int:
		serialized, err = serializer.Serialize(expected)
	case int8:
		serialized, err = serializer.Serialize(expected)
	case int16:
		serialized, err = serializer.Serialize(expected)
	case int32:
		serialized, err = serializer.Serialize(expected)
	case int64:
		serialized, err = serializer.Serialize(expected)
	}

	return
}

func serializeUint(serializer serializing.Algorithm, expected interface{}) (serialized []byte, err error) {
	switch expected := expected.(type) {
	case uint:
		serialized, err = serializer.Serialize(expected)
	case uint8:
		serialized, err = serializer.Serialize(expected)
	case uint16:
		serialized, err = serializer.Serialize(expected)
	case uint32:
		serialized, err = serializer.Serialize(expected)
	case uint64:
		serialized, err = serializer.Serialize(expected)
	}

	return
}

func unserialize(serializer serializing.Algorithm, serialized []byte, target interface{}) (actual interface{}, err error) {
	switch temp := target.(type) {
	case bool:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case []byte:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case []rune:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case string:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case testStruct:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case complex64, complex128, float32, float64, time.Time:
		actual, err = unserializeNumeric(serializer, serialized, target)
	case int, int8, int16, int32, int64:
		actual, err = unserializeInt(serializer, serialized, target)
	case uint, uint8, uint16, uint32, uint64:
		actual, err = unserializeUint(serializer, serialized, target)
	default:
		err = fmt.Errorf("unsupported value %s(%v)", reflect.TypeOf(actual), actual)
	}

	return
}

func unserializeNumeric(serializer serializing.Algorithm, serialized []byte, target interface{}) (actual interface{}, err error) {
	switch temp := target.(type) {
	case complex64:
		var temp2 []byte
		err = serializer.Unserialize(serialized, &temp2)
		if err == nil {
			err = binary.Read(bytes.NewBuffer(temp2), binary.LittleEndian, &temp)
			actual = temp
		}
	case complex128:
		var temp2 []byte
		err = serializer.Unserialize(serialized, &temp2)
		if err == nil {
			err = binary.Read(bytes.NewBuffer(temp2), binary.LittleEndian, &temp)
			actual = temp
		}
	case float32:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case float64:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case time.Time:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	}

	return
}

func unserializeInt(serializer serializing.Algorithm, serialized []byte, target interface{}) (actual interface{}, err error) {
	switch temp := target.(type) {
	case int:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case int8:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case int16:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case int32:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case int64:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	}

	return
}

func unserializeUint(serializer serializing.Algorithm, serialized []byte, target interface{}) (actual interface{}, err error) {
	switch temp := target.(type) {
	case uint:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case uint8:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case uint16:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case uint32:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	case uint64:
		err = serializer.Unserialize(serialized, &temp)
		actual = temp
	}

	return
}

type testStruct struct {
	Bool      bool
	ByteSlice []byte
	Float     float64
	Int       int64
	Rune      rune
	RuneSlice []rune
	String    string
	Time      time.Time
	Uint      uint64
}

// Equal ::: Struct
func (actual testStruct) Equal(expected testStruct) bool {
	return actual.Bool == expected.Bool &&
		bytes.Equal(actual.ByteSlice, expected.ByteSlice) &&
		actual.Float == expected.Float &&
		actual.Int == expected.Int &&
		actual.Rune == expected.Rune &&
		reflect.DeepEqual(actual.RuneSlice, expected.RuneSlice) &&
		actual.String == expected.String &&
		actual.Time.Equal(expected.Time) &&
		actual.Uint == expected.Uint
}
