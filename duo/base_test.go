package duo

import (
	"testing"
	"time"

	"github.com/bouk/monkey"
	"github.com/stretchr/testify/assert"
)

func TestHmacSha1(t *testing.T) {
	secret := "secret"
	message := "message"

	actual := hmacSha1(secret, message)
	expected := "0caf649feee4953d87bf903ac1176c45e028df16"
	assert.Equal(t, actual, expected)
}

func TestSignPayload(t *testing.T) {
	death := time.Date(1999, time.December, 31, 23, 59, 59, 999, time.UTC)
	patch := monkey.Patch(time.Now, func() time.Time { return death })
	defer patch.Unpatch()

	secret := "secret"
	payload := []string{"username", "key"}
	prefix := duoPrefix
	ttl := duoExpiration

	actual := signPayload(secret, payload, prefix, ttl)
	expected := "TX|dXNlcm5hbWV8a2V5fDk0NjY4NTA5OQ==|0047894ee8fc935b176b2cac2c57b358150471fc"
	assert.Equal(t, actual, expected)
}
