package middleware

import (
	"authorization_flow_oauth/internal/store"
	"authorization_flow_oauth/pkg/auth"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
)

type TokenClaims struct {
	// Common claims
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Username string `json:"preferred_username"`
	Name     string `json:"name"`

	// Access token specific claims
	Scope       string `json:"scope"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`

	// Add other claims you need
}

// AuthMiddleware validates the session before allowing access to protected pages
func AuthMiddleware(sessionStore store.SessionStore, authClient *auth.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for session_id cookie
		sessionID, err := c.Cookie("session_id")
		if err != nil || sessionID == "" {
			// No valid session found, redirect to login page
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Check for user_email cookie
		userEmail, err := c.Cookie("user_email")
		if err != nil || userEmail == "" {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		// Step 2: Validate SessionID in Redis/DB
		// This is a quick check to see if the session is still valid
		// and not revoked
		sessionData, err := sessionStore.GetSession(c, sessionID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid session",
			})
			c.Abort()
			return
		}
		if sessionData.AccessToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid session not found",
			})
			c.Abort()
			return
		}
		if authClient.Provider == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "OIDC provider not initialized",
			})
			c.Abort()
			return
		}
		// Get Keycloak's public key set
		keySet := authClient.Provider.VerifierContext(c, &oidc.Config{
			SkipClientIDCheck: true,
		})
		if keySet == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid to verify provider access token",
			})
			c.Abort()
			return
		}
		// Verify the token
		token, err := keySet.Verify(c, sessionData.AccessToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid verify access token",
			})
			c.Abort()
			return
		}
		// Parse claims
		var claims TokenClaims
		if err := token.Claims(&claims); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid parse claims",
			})
			c.Abort()
			return
		}

		// _, err = authClient.OIDC.Verify(c, sessionData.AccessToken)
		// if err != nil {
		// 	c.JSON(http.StatusUnauthorized, gin.H{
		// 		"error": "Invalid verify access token",
		// 	})
		// 	c.Abort()
		// 	return
		// }
		// Store validated user info in context for the handler to use
		c.Set("user_id", sessionID)
		c.Set("user_email", userEmail)

		c.Next()
	}
}
