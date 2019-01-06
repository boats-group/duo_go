package duo

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	logrus "github.com/sirupsen/logrus"
)

const (
	errParsePayloadInvalidPayload    = "invalid payload format"
	errParsePayloadInvalidSignature  = "signature hash does not match"
	errParsePayloadInvalidPrefix     = "payload prefix does not match"
	errParsePayloadInvalidContent    = "payload content is invalid"
	errParsePayloadInvalidExpiration = "payload expiration is invalid"
	errParsePayloadInvalidKey        = "payload key does not match"
	errParsePayloadInvalidUsername   = "payload username is invalid"
)

var (
	duoPrefix           = "TX"
	appPrefix           = "APP"
	authPrefix          = "AUTH"
	enrollPrefix        = "ENROLL"
	enrollRequestPrefix = "ENROLL_REQUEST"

	duoExpiration = 300
	appExpiration = 3600

	integrationKeyLen = 20
	secretKeyLen      = 40
	appKeyLen         = 40
)

func hmacSha1(secret string, message string) string {
	hash := hmac.New(sha1.New, []byte(secret))
	hash.Write([]byte(message))
	checksum := hex.EncodeToString(hash.Sum(nil))

	return checksum
}

func signPayload(secret string, payload []string, prefix string, ttl int) string {
	logrus.WithFields(logrus.Fields{
		"secret":  secret,
		"payload": strings.Join(payload, "|"),
		"prefix":  prefix,
		"ttl":     ttl,
	}).Debug("signPayload:in")

	expiration := strconv.FormatInt(time.Now().Local().Add(time.Second*time.Duration(ttl)).Unix(), 10)
	content := strings.Join(append(payload, []string{expiration}...), "|")
	encodedContent := base64.StdEncoding.EncodeToString([]byte(content))
	cookie := fmt.Sprintf("%s|%s", prefix, encodedContent)
	signature := hmacSha1(secret, cookie)

	logrus.WithFields(logrus.Fields{
		"expiration": expiration,
		"content":    content,
		"cookie":     cookie,
		"signature":  signature,
	}).Debug("signPayload:out")

	return fmt.Sprintf("%s|%s", cookie, signature)
}

func parsePayload(secret string, payload string, prefix string, key string) (string, error) {
	logrus.WithFields(logrus.Fields{
		"secret":  secret,
		"payload": payload,
		"prefix":  prefix,
		"key":     key,
	}).Debug("parsePayload:in")

	// Parse payload data
	payloadValues := strings.Split(payload, "|")
	if len(payloadValues) != 3 {
		return "", errors.New(errParsePayloadInvalidPayload)
	}

	// Validate payload signature (HMAC-SHA1)
	payloadPrefix, payloadContent, payloadSignature := payloadValues[0], payloadValues[1], payloadValues[2]
	payloadCookie := fmt.Sprintf("%s|%s", payloadPrefix, payloadContent)
	signature := hmacSha1(secret, payloadCookie)
	if !hmac.Equal([]byte(hmacSha1(secret, payloadSignature)), []byte(hmacSha1(secret, signature))) {
		return "", errors.New(errParsePayloadInvalidSignature)
	}

	// Validate payload prefix
	if payloadPrefix != prefix {
		return "", errors.New(errParsePayloadInvalidPrefix)
	}

	// Validate payload content (Base64)
	decodedContent, err := base64.StdEncoding.DecodeString(payloadContent)
	contentValues := strings.Split(string(decodedContent), "|")
	if err != nil || len(contentValues) != 3 {
		return "", errors.New(errParsePayloadInvalidContent)
	}

	// Validate payload expiration
	timestamp := time.Now().Local().Unix()
	payloadExpiration, err := strconv.ParseInt(contentValues[2], 10, 64)
	if err != nil || payloadExpiration < timestamp {
		return "", errors.New(errParsePayloadInvalidExpiration)
	}

	// Validate payload key
	payloadKey := contentValues[1]
	if payloadKey != key {
		return "", errors.New(errParsePayloadInvalidKey)
	}

	// Validate payload username
	payloadUsername := contentValues[0]
	if payloadUsername == "" {
		return "", errors.New(errParsePayloadInvalidUsername)
	}

	return payloadUsername, nil
}
