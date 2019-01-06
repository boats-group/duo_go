package duo

import (
	"testing"
	"time"

	"github.com/bouk/monkey"
	"github.com/stretchr/testify/assert"
)

var (
	defaultUsername       = "tester"
	defaultIntegrationKey = "abcdefghijklmnopqrst"
	defaultApplicationKey = "abcdefghijklmnopqrstuvwxyz1234567890!@#$"
	defaultSecretKey      = "abcdefghijklmnopqrstuvwxyz1234567890!@#$"
	defaultHash           = "7402d46db372a8be0dcc3baa2570c87370055b44"
	defaultSignature      = "TX|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|5e7b669b043b01060d56f86871abd1190a2491ec"
	defaultEpochPast      = time.Date(1999, time.December, 31, 23, 59, 59, 999, time.UTC)
	defaultEpochFuture    = time.Date(2099, time.December, 31, 23, 59, 59, 999, time.UTC)
)

func TestHmacSha1WithDefaults(t *testing.T) {
	actual := hmacSha1(defaultSecretKey, defaultUsername)
	assert.Equal(t, defaultHash, actual)
}

func TestSignPayloadWithDefaults(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := []string{defaultUsername, defaultIntegrationKey}
	actual := signPayload(defaultSecretKey, payload, duoPrefix, duoExpiration)
	assert.Equal(t, defaultSignature, actual)
}

func TestParsePayloadWithDefaults(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	actual, _ := parsePayload(defaultSecretKey, defaultSignature, duoPrefix, defaultIntegrationKey)
	assert.Equal(t, defaultUsername, actual)
}

func TestParsePayloadWithInvalidPayload(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := ""
	_, err := parsePayload(defaultSecretKey, payload, duoPrefix, defaultIntegrationKey)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errParsePayloadInvalidPayload, err.Error())
	}
}

func TestParsePayloadWithInvalidSignature(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := "TX|testerabcdefghijklmnopqrst946685099|"
	_, err := parsePayload(defaultSecretKey, payload, duoPrefix, defaultIntegrationKey)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errParsePayloadInvalidSignature, err.Error())
	}
}

func TestParsePayloadWithInvalidContent(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := "TX|testerabcdefghijklmnopqrst946685099|b3727c62edab9eaafa52ea8bc72a77c29d6e31fa"
	_, err := parsePayload(defaultSecretKey, payload, duoPrefix, defaultIntegrationKey)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errParsePayloadInvalidContent, err.Error())
	}
}

func TestParsePayloadWithInvalidPrefix(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := "NIL"
	_, err := parsePayload(defaultSecretKey, defaultSignature, payload, defaultIntegrationKey)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errParsePayloadInvalidPrefix, err.Error())
	}
}

func TestParsePayloadWithInvalidExpiration(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochFuture })
	defer patch.Unpatch()

	_, err := parsePayload(defaultSecretKey, defaultSignature, duoPrefix, defaultIntegrationKey)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errParsePayloadInvalidExpiration, err.Error())
	}
}

func TestParsePayloadWithInvalidKey(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := ""
	_, err := parsePayload(defaultSecretKey, defaultSignature, duoPrefix, payload)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errParsePayloadInvalidKey, err.Error())
	}
}

func TestParsePayloadWithInvalidUsername(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := "TX|fGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|3195c2bee68972654e1fd41c6e2f25ae584493cd"
	_, err := parsePayload(defaultSecretKey, payload, duoPrefix, defaultIntegrationKey)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errParsePayloadInvalidUsername, err.Error())
	}
}
