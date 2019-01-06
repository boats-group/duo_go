package duo

import (
	"testing"
	"time"

	"github.com/bouk/monkey"
	"github.com/stretchr/testify/assert"
)

var (
	defaultResponseSignature       = "AUTH|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|138336652235ffff93fdb1ef036059e8e9db2939:APP|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4ODM5OQ==|b36dd884e2f4617842da5a96862e28b1365a1227"
	defaultResponseEnrollSignature = "ENROLL|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|99b9c6241021308887d6a91b0ae20f177bf21852:APP|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4ODM5OQ==|b36dd884e2f4617842da5a96862e28b1365a1227"
)

func TestVerifyResponseWithDefaults(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	actual, _ := VerifyResponse(defaultIntegrationKey, defaultSecretKey, defaultApplicationKey, defaultResponseSignature)
	assert.Equal(t, defaultUsername, actual)
}

func TestVerifyEnrollResponseWithDefaults(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	actual, _ := VerifyEnrollResponse(defaultIntegrationKey, defaultSecretKey, defaultApplicationKey, defaultResponseEnrollSignature)
	assert.Equal(t, defaultUsername, actual)
}

func TestVerifyResponseWithInvalidResponse(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := ""
	_, err := VerifyResponse(defaultIntegrationKey, defaultSecretKey, defaultApplicationKey, payload)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errVerifyResponseInvalidResponse, err.Error())
	}
}

func TestVerifyResponseWithInvalidAuthSignature(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := "AUTH|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|:APP|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4ODM5OQ==|b36dd884e2f4617842da5a96862e28b1365a1227"
	_, err := VerifyResponse(defaultIntegrationKey, defaultSecretKey, defaultApplicationKey, payload)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errVerifyResponseInvalidAuthSignature, err.Error())
	}
}

func TestVerifyResponseWithInvalidAppSignature(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := "AUTH|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|138336652235ffff93fdb1ef036059e8e9db2939:APP|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4ODM5OQ==|"
	_, err := VerifyResponse(defaultIntegrationKey, defaultSecretKey, defaultApplicationKey, payload)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errVerifyResponseInvalidAppSignature, err.Error())
	}
}

func TestVerifyResponseWithInvalidUsername(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	payload := "AUTH|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|138336652235ffff93fdb1ef036059e8e9db2939:APP|cmV0c2V0fGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4ODM5OQ==|de079f29930cb63e6b36e2b226ec59ea76a9ccae"
	_, err := VerifyResponse(defaultIntegrationKey, defaultSecretKey, defaultApplicationKey, payload)
	if assert.Errorf(t, err, "") {
		assert.Equal(t, errVerifyResponseInvalidUsername, err.Error())
	}
}
