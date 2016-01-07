package secure551

import (
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
