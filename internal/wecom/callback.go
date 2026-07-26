package wecom

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type CallbackCipher struct {
	token, corpID string
	key           []byte
}
type CallbackEvent struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`
	FromUserName string   `xml:"FromUserName"`
	CreateTime   int64    `xml:"CreateTime"`
	MsgType      string   `xml:"MsgType"`
	Event        string   `xml:"Event"`
	ChangeType   string   `xml:"ChangeType"`
	UserID       string   `xml:"UserID"`
	NewUserID    string   `xml:"NewUserID"`
	DepartmentID string   `xml:"Id"`
	ParentID     string   `xml:"ParentId"`
}
type encryptedEnvelope struct {
	Encrypt string `xml:"Encrypt"`
}

func NewCallbackCipher(token, encodingAESKey, corpID string) (*CallbackCipher, error) {
	if token == "" || encodingAESKey == "" || corpID == "" {
		return nil, errors.New("企业微信回调 Token、EncodingAESKey 和 CorpID 不能为空")
	}
	if len(encodingAESKey) != 43 {
		return nil, errors.New("企业微信 EncodingAESKey 必须为 43 个字符")
	}
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil || len(key) != 32 {
		return nil, errors.New("企业微信 EncodingAESKey 无效")
	}
	return &CallbackCipher{token: token, corpID: corpID, key: key}, nil
}

func (c *CallbackCipher) VerifyAndDecrypt(signature, timestamp, nonce, encrypted string) ([]byte, error) {
	if !constantEqual(signature, c.signature(timestamp, nonce, encrypted)) {
		return nil, errors.New("企业微信回调签名无效")
	}
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, errors.New("企业微信回调密文不是有效 Base64")
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return nil, errors.New("企业微信回调密文长度无效")
	}
	plain := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, c.key[:aes.BlockSize]).CryptBlocks(plain, raw)
	plain, err = pkcs7Unpad(plain, 32)
	if err != nil {
		return nil, err
	}
	if len(plain) < 20 {
		return nil, errors.New("企业微信回调明文过短")
	}
	messageLength := int(binary.BigEndian.Uint32(plain[16:20]))
	if messageLength < 0 || 20+messageLength > len(plain) {
		return nil, errors.New("企业微信回调消息长度无效")
	}
	message, receiver := plain[20:20+messageLength], string(plain[20+messageLength:])
	if receiver != c.corpID {
		return nil, errors.New("企业微信回调 CorpID 不匹配")
	}
	return message, nil
}

func (c *CallbackCipher) ParseEvent(signature, timestamp, nonce, body string) (CallbackEvent, error) {
	var envelope encryptedEnvelope
	if err := xml.Unmarshal([]byte(body), &envelope); err != nil || envelope.Encrypt == "" {
		return CallbackEvent{}, errors.New("企业微信回调 XML 无效")
	}
	plain, err := c.VerifyAndDecrypt(signature, timestamp, nonce, envelope.Encrypt)
	if err != nil {
		return CallbackEvent{}, err
	}
	var event CallbackEvent
	if err := xml.Unmarshal(plain, &event); err != nil {
		return CallbackEvent{}, fmt.Errorf("企业微信事件 XML 无效: %w", err)
	}
	return event, nil
}

func (c *CallbackCipher) signature(values ...string) string {
	values = append(values, c.token)
	sort.Strings(values)
	digest := sha1.Sum([]byte(strings.Join(values, "")))
	return hex.EncodeToString(digest[:])
}

func pkcs7Unpad(value []byte, blockSize int) ([]byte, error) {
	if len(value) == 0 {
		return nil, errors.New("企业微信回调填充为空")
	}
	padding := int(value[len(value)-1])
	if padding < 1 || padding > blockSize || padding > len(value) {
		return nil, errors.New("企业微信回调填充无效")
	}
	if !bytes.Equal(value[len(value)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		return nil, errors.New("企业微信回调填充校验失败")
	}
	return value[:len(value)-padding], nil
}

func constantEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
