package main

import (
	"log"
	"net/http"
)

// Error codes for user-facing errors
const (
	// Authentication errors (AUTH001-AUTH099)
	ErrAuthInvalidCredentials = "AUTH001"
	ErrAuthTokenInvalid       = "AUTH002"
	ErrAuthTokenExpired       = "AUTH003"
	ErrAuthRateLimited        = "AUTH004"

	// Firewall errors (FW001-FW099)
	ErrFirewallAddFailed    = "FW001"
	ErrFirewallDeleteFailed = "FW002"
	ErrFirewallInvalidRule  = "FW003"
	ErrFirewallListFailed   = "FW004"

	// Interface errors (IF001-IF099)
	ErrInterfaceNotFound     = "IF001"
	ErrInterfaceCreateFailed = "IF002"
	ErrInterfaceDeleteFailed = "IF003"
	ErrInterfaceConfigFailed = "IF004"

	// Network/NAT errors (NET001-NET099)
	ErrNetworkInvalidIP        = "NET001"
	ErrNetworkPortInvalid      = "NET002"
	ErrNetworkRuleAddFailed    = "NET003"
	ErrNetworkRuleDeleteFailed = "NET004"

	// DHCP errors (DHCP001-DHCP099)
	ErrDHCPConfigFailed = "DHCP001"
	ErrDHCPInvalidRange = "DHCP002"
	ErrDHCPSaveFailed   = "DHCP003"

	// System errors (SYS001-SYS099)
	ErrSystemConfigLoad     = "SYS001"
	ErrSystemConfigSave     = "SYS002"
	ErrSystemBackupFailed   = "SYS003"
	ErrSystemRestoreFailed  = "SYS004"
	ErrSystemServiceControl = "SYS005"

	// VPN errors (VPN001-VPN099)
	ErrVPNConfigInvalid = "VPN001"
	ErrVPNControlFailed = "VPN002"
	ErrVPNCreateFailed  = "VPN003"

	// Generic errors (GEN001-GEN099)
	ErrGenericInvalidRequest = "GEN001"
	ErrGenericInternalError  = "GEN002"
	ErrGenericNotFound       = "GEN003"
	ErrGenericForbidden      = "GEN004"
)

// SanitizedError creates a user-facing error message with error code
type SanitizedError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// newSanitizedError creates a sanitized error response
func newSanitizedError(code, userMessage string) SanitizedError {
	return SanitizedError{
		Code:    code,
		Message: userMessage,
	}
}

// respondWithError sends a sanitized error response
func respondWithError(w http.ResponseWriter, code string, userMessage string, httpStatus int, internalError error) {
	// Log internal error for debugging
	if internalError != nil {
		log.Printf("[ERROR %s] %s: %v", code, userMessage, internalError)
	} else {
		log.Printf("[ERROR %s] %s", code, userMessage)
	}

	// Send sanitized error to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	writeJSON(w, newSanitizedError(code, userMessage))
}

// Common error responses
func respondAuthError(w http.ResponseWriter, message string, internalErr error) {
	respondWithError(w, ErrAuthInvalidCredentials, message, http.StatusUnauthorized, internalErr)
}

func respondFirewallError(w http.ResponseWriter, code, message string, internalErr error) {
	respondWithError(w, code, message, http.StatusInternalServerError, internalErr)
}

func respondNetworkError(w http.ResponseWriter, code, message string, internalErr error) {
	respondWithError(w, code, message, http.StatusBadRequest, internalErr)
}

func respondSystemError(w http.ResponseWriter, code, message string, internalErr error) {
	respondWithError(w, code, message, http.StatusInternalServerError, internalErr)
}

func respondInvalidRequest(w http.ResponseWriter, message string) {
	respondWithError(w, ErrGenericInvalidRequest, message, http.StatusBadRequest, nil)
}
