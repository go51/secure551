package secure551

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"github.com/go51/string551"
	"strconv"
	"time"
)

var hashLoop int = 512
var byteList []byte = string551.StringToBytes("0123456789abcdef")

func Hash() string {
	rand := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
	sha := sha256.Sum256(string551.StringToBytes(rand))
	for i := 0; i < hashLoop; i++ {
		sha = sha256.Sum256(sha[:])
	}

	ret := make([]byte, 0, 64)

	for i := 0; i < len(sha); i++ {
		v := sha[i]
		m := v % 16
		s := (v - m) / 16

		ret = append(ret, byteList[s])
		ret = append(ret, byteList[m])
	}

	return string551.BytesToString(ret)
}

func PasswordToHash(password, salt string) string {

	sha := sha256.Sum256(string551.StringToBytes(string551.Join(salt, password)))
	for i := 0; i < hashLoop; i++ {
		sha = sha256.Sum256(sha[:])
	}

	ret := make([]byte, 0, 64)

	for i := 0; i < len(sha); i++ {
		v := sha[i]
		m := v % 16
		s := (v - m) / 16

		ret = append(ret, byteList[s])
		ret = append(ret, byteList[m])
	}

	return string551.BytesToString(ret)

}

var chars = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

func Encrypted(src, key string) string {
	aesInstance, err := aes.NewCipher(string551.StringToBytes(key))
	if err != nil {
		panic(err)
	}

	bytes := string551.StringToBytes(src)

	cfb := cipher.NewCFBEncrypter(aesInstance, chars)
	cipherText := make([]byte, len(bytes))
	cfb.XORKeyStream(cipherText, bytes)

	ret := make([]byte, 0, len(cipherText)*2)

	for i := 0; i < len(cipherText); i++ {
		v := cipherText[i]
		m := v % 16
		s := (v - m) / 16

		ret = append(ret, byteList[s])
		ret = append(ret, byteList[m])
	}

	return string551.BytesToString(ret)

}

var numByteList = map[byte]int{0x30: 0, 0x31: 1, 0x32: 2, 0x33: 3, 0x34: 4, 0x35: 5, 0x36: 6, 0x37: 7, 0x38: 8, 0x39: 9, 0x61: 10, 0x62: 11, 0x63: 12, 0x64: 13, 0x65: 14, 0x66: 15}

func Decrypted(src, key string) string {
	bytes := string551.StringToBytes(src)

	text := make([]byte, 0, len(src)*3)

	for i := 0; i < len(bytes); i += 2 {
		v := numByteList[bytes[i]] * 16
		v += numByteList[bytes[i+1]]
		text = append(text, byte(v))
	}

	aesInstance, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	cfbdec := cipher.NewCFBDecrypter(aesInstance, chars)
	plaintextCopy := make([]byte, len(text))
	cfbdec.XORKeyStream(plaintextCopy, text)

	return string551.BytesToString(plaintextCopy)
}
