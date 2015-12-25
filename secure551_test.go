package secure551_test

import (
	"github.com/go51/secure551"
	"testing"
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
