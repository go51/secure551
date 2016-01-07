package secure551_test

import (
	"github.com/go51/secure551"
	"testing"
	"time"
)

func TestHash(t *testing.T) {
	ret := secure551.Hash()

	if len(ret) != 64 {
		t.Errorf("ハッシュの生成に失敗しました。\nRet: ", ret)
	}

	if ret == "" {
		t.Errorf("ハッシュの生成に失敗しました。\nRet: %s", ret)
	}
}

func BenchmarkHash(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = secure551.Hash()
	}

}

func TestPasswordToHash(t *testing.T) {
	password := "sample_password_1105"
	salt1 := secure551.Hash()
	time.Sleep(1 * time.Millisecond)
	salt2 := secure551.Hash()

	ret1 := secure551.PasswordToHash(password, salt1)
	ret2 := secure551.PasswordToHash(password, salt2)

	//	log.Printf("Salt 1: %s\n", salt1)
	//	log.Printf("Salt 2: %s\n", salt2)
	//	log.Printf("Ret 1: %s\n", ret1)
	//	log.Printf("Ret 2: %s\n", ret2)

	if len(ret1) != 64 {
		t.Errorf("ハッシュの生成に失敗しました。\nRet: ", ret1)
	}
	if len(ret2) != 64 {
		t.Errorf("ハッシュの生成に失敗しました。\nRet: ", ret2)
	}

	if ret1 == ret2 {
		t.Errorf("ハッシュの生成に失敗しました。\nRet 1: %s\nRet 2: %s\n", ret1, ret2)
	}

}

func BenchmarkPasswordToHash(b *testing.B) {
	password := "sample_password_1105"
	salt := secure551.Hash()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = secure551.PasswordToHash(password, salt)
	}
}

func TestEncrypted(t *testing.T) {
	src := "sample_string"
	key1 := "string---------32---------string"
	key2 := "string--------3--2--------string"

	ret1 := secure551.Encrypted(src, key1)
	ret2 := secure551.Encrypted(src, key2)

	if ret1 == "" {
		t.Errorf("文字列の暗号化に失敗しました。\nRet: %s\n", ret1)
	}
	if ret1 != "00285a12ed2484e1a41b2c987e" {
		t.Errorf("文字列の暗号化に失敗しました。\nRet: %s\n", ret1)
	}

	if ret2 == "" {
		t.Errorf("文字列の暗号化に失敗しました。\nRet: %s\n", ret2)
	}
	if ret2 != "eef8cfbaf79f19a5f3160c46d0" {
		t.Errorf("文字列の暗号化に失敗しました。\nRet: %s\n", ret2)
	}
	if ret1 == ret2 {
		t.Errorf("文字列の暗号化に失敗しました。\nRet2: %s\nRet1: %s\n", ret1, ret2)
	}
}

func BenchmarkEncrypted(b *testing.B) {
	src := "sample_string"
	key := "string---------32---------string"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = secure551.Encrypted(src, key)
	}

}

func TestDecrypted(t *testing.T) {
	src := "sample_string"
	key1 := "string---------32---------string"
	key2 := "string--------3--2--------string"
	enc := secure551.Encrypted(src, key1)
	ret1 := secure551.Decrypted(enc, key1)
	ret2 := secure551.Decrypted(enc, key2)

	if ret1 != src {
		t.Errorf("文字列の復号化に失敗しました。\nRet: %s\n", ret1)
	}
	if ret2 == src {
		t.Errorf("文字列の復号化に失敗しました。\nRet: %s\n", ret2)
	}

}

func BenchmarkDecrypted(b *testing.B) {
	src := "sample_string"
	key := "string---------32---------string"
	enc := secure551.Encrypted(src, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = secure551.Decrypted(enc, key)
	}
}
