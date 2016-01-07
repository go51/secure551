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
