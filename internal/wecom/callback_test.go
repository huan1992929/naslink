package wecom

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestCallbackVerifyAndParse(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	encodedKey := strings.TrimSuffix(base64.StdEncoding.EncodeToString(key), "=")
	callback, err := NewCallbackCipher("token", encodedKey, "wwcorp")
	if err != nil {
		t.Fatal(err)
	}
	xmlBody := `<xml><ToUserName><![CDATA[wwcorp]]></ToUserName><Event><![CDATA[change_contact]]></Event><ChangeType><![CDATA[update_user]]></ChangeType><UserID><![CDATA[zhangsan]]></UserID></xml>`
	encrypted := encryptForTest(t, key, []byte(xmlBody), "wwcorp")
	signature := callback.signature("1700000000", "nonce", encrypted)
	event, err := callback.ParseEvent(signature, "1700000000", "nonce", `<xml><Encrypt><![CDATA[`+encrypted+`]]></Encrypt></xml>`)
	if err != nil {
		t.Fatal(err)
	}
	if event.Event != "change_contact" || event.ChangeType != "update_user" || event.UserID != "zhangsan" {
		t.Fatalf("unexpected event: %#v", event)
	}
	if _, err := callback.VerifyAndDecrypt("bad", "1700000000", "nonce", encrypted); err == nil {
		t.Fatal("bad signature accepted")
	}
}

func encryptForTest(t *testing.T, key, message []byte, corpID string) string {
	t.Helper()
	plain := append([]byte("0123456789abcdef"), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(plain[16:20], uint32(len(message)))
	plain = append(plain, message...)
	plain = append(plain, []byte(corpID)...)
	padding := 32 - len(plain)%32
	plain = append(plain, make([]byte, padding)...)
	for i := len(plain) - padding; i < len(plain); i++ {
		plain[i] = byte(padding)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, key[:16]).CryptBlocks(encrypted, plain)
	return base64.StdEncoding.EncodeToString(encrypted)
}
