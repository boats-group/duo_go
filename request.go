package duo

import (
	"fmt"
)

func signRequest(integrationKey string, secretKey string, appKey string, username string, prefix string) (string, error) {
	payload := []string{username, integrationKey}
	duoSignature := signPayload(secretKey, payload, prefix, duoExpiration)
	appSignature := signPayload(appKey, payload, appPrefix, appExpiration)

	return fmt.Sprintf("%s:%s", duoSignature, appSignature), nil
}

// SignRequest ...
func SignRequest(integrationKey string, secretKey string, appKey string, username string) (string, error) {
	return signRequest(integrationKey, secretKey, appKey, username, duoPrefix)
}

// SignEnrollRequest ...
func SignEnrollRequest(integrationKey string, secretKey string, appKey string, username string) (string, error) {
	return signRequest(integrationKey, secretKey, appKey, username, enrollRequestPrefix)
}
