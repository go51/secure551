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
