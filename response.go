package duo

import (
	"fmt"
	"strings"
)

const (
	errVerifyResponseInvalidResponse      = "received invalid server response"
	errVerifyResponseInvalidAuthSignature = "failed to validate authentication signature"
	errVerifyResponseInvalidAppSignature  = "failed to validate application signature"
	errVerifyResponseInvalidUsername      = "usernames do not match"
)

func verifyResponse(integrationKey string, secretKey string, appKey string, prefix string, response string) (string, error) {
	values := strings.Split(response, ":")
	if len(values) != 2 {
		return "", fmt.Errorf(errVerifyResponseInvalidResponse)
	}

	// Validate response authentication signature
	authSignature := values[0]
	authUsername, err := parsePayload(secretKey, authSignature, prefix, integrationKey)
	if err != nil {
		return "", fmt.Errorf(errVerifyResponseInvalidAuthSignature)
	}

	// Validate response application signature
	appSignature := values[1]
	appUsername, err := parsePayload(appKey, appSignature, appPrefix, integrationKey)
	if err != nil {
		return "", fmt.Errorf(errVerifyResponseInvalidAppSignature)
	}

	// Validate response usernames
	if authUsername != appUsername {
		return "", fmt.Errorf(errVerifyResponseInvalidUsername)
	}

	return authUsername, nil
}

// VerifyResponse ...
func VerifyResponse(integrationKey string, secretKey string, appKey string, response string) (string, error) {
	return verifyResponse(integrationKey, secretKey, appKey, authPrefix, response)
}

// VerifyEnrollResponse ...
func VerifyEnrollResponse(integrationKey string, secretKey string, appKey string, response string) (string, error) {
	return verifyResponse(integrationKey, secretKey, appKey, enrollPrefix, response)
}
