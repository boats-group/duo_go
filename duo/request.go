package duo

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

func signRequest(integrationKey string, secretKey string, appKey string, username string, prefix string) (string, error) {
	log.WithFields(log.Fields{
		"ikey":   integrationKey,
		"skey":   secretKey,
		"akey":   appKey,
		"user":   username,
		"prefix": prefix,
	}).Debug("signRequest(in)")

	payload := []string{username, integrationKey}
	duoSignature := signPayload(secretKey, payload, prefix, duoExpiration)
	appSignature := signPayload(appKey, payload, appPrefix, appExpiration)

	log.WithFields(log.Fields{
		"dsig": duoSignature,
		"asig": appSignature,
	}).Debug("signRequest(out)")

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
