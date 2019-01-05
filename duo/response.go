package duo

import (
	"fmt"
	"strings"
)

func verifyResponse(integrationKey string, secretKey string, appKey string, prefix string, response string) (string, error) {
	values := strings.Split(response, ":")
	if len(values) != 2 {
		return "", fmt.Errorf("received invalid server response")
	}

	authSignature := values[0]
	authUsername, err := parsePayload(secretKey, authSignature, prefix, integrationKey)
	if err != nil {
		return "", fmt.Errorf("failed to validate authentication signature: %v", err)
	}

	appSignature := values[1]
	appUsername, err := parsePayload(appKey, appSignature, appPrefix, integrationKey)
	if err != nil {
		return "", fmt.Errorf("failed to validate application signature: %v", err)
	}

	if authUsername != appUsername {
		return "", fmt.Errorf("username does not match")
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
