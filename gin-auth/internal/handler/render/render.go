package render

import (
	"authorization_flow_oauth/internal/config"
	"net/http"

	"github.com/gin-gonic/gin"
)

type RenderHandler struct {
	cfg *config.Config
}

func New(
	cfg *config.Config,
) *RenderHandler {
	return &RenderHandler{
		cfg: cfg,
	}
}

func (r *RenderHandler) SuccessLogin(c *gin.Context) {
	// / Get user info from context (set by middleware)
	userID, _ := c.Get("user_id")
	userEmail, _ := c.Get("user_email")
	c.HTML(http.StatusOK, "login/success.tmpl", gin.H{
		"Title":        "Login Successful",
		"Message":      "You have successfully logged in!",
		"Username":     userID,
		"Email":        userEmail,
		"DashboardURL": "/dashboard",
		"LogoutURL":    "/logout",
	})
}
