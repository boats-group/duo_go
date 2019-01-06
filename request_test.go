package duo

import (
	"testing"
	"time"

	"github.com/bouk/monkey"
	"github.com/stretchr/testify/assert"
)

var (
	defaultRequestSignature       = "TX|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|5e7b669b043b01060d56f86871abd1190a2491ec:APP|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4ODM5OQ==|b36dd884e2f4617842da5a96862e28b1365a1227"
	defaultRequestEnrollSignature = "ENROLL_REQUEST|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4NTA5OQ==|9aea948bb78d756ea3dd17bdbe039ab0a997d0ef:APP|dGVzdGVyfGFiY2RlZmdoaWprbG1ub3BxcnN0fDk0NjY4ODM5OQ==|b36dd884e2f4617842da5a96862e28b1365a1227"
)

func TestSignRequestWithDefaults(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	actual, _ := SignRequest(defaultIntegrationKey, defaultSecretKey, defaultApplicationKey, defaultUsername)
	assert.Equal(t, defaultRequestSignature, actual)
}

func TestSignRequestEnrollWithDefaults(t *testing.T) {
	patch := monkey.Patch(time.Now, func() time.Time { return defaultEpochPast })
	defer patch.Unpatch()

	actual, _ := SignEnrollRequest(defaultIntegrationKey, defaultSecretKey, defaultApplicationKey, defaultUsername)
	assert.Equal(t, defaultRequestEnrollSignature, actual)
}
