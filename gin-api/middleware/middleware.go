package middleware

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type JWTValidator struct {
	jwks     *JWKS
	issuer   string
	audience string
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func GetJWKS(realmURL string) (*JWKS, error) {
	// Keycloak JWKS endpoint
	jwksURL := fmt.Sprintf("%s/protocol/openid-connect/certs", realmURL)

	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	return &jwks, nil
}

func (jwks *JWKS) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	for _, jwk := range jwks.Keys {
		if jwk.Kid == kid && jwk.Kty == "RSA" {
			return jwkToPublicKey(jwk)
		}
	}
	return nil, fmt.Errorf("key not found for kid: %s", kid)
}

func jwkToPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// 解码 n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	// 解码 e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()

	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}

func NewJWTValidator(issuer, audience string) *JWTValidator {
	jwks, err := GetJWKS(issuer)
	if err != nil {
		fmt.Println("Error getting JWKS:", err)
		return nil
	}

	return &JWTValidator{
		jwks:     jwks,
		issuer:   issuer,
		audience: audience,
	}
}

func (v *JWTValidator) Middleware() gin.HandlerFunc {
	return v.MiddlewareWithScope()
}

func (v *JWTValidator) MiddlewareWithScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		log.Println(tokenString)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// 验证签名算法
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// 获取 kid
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("kid not found in token header")
			}

			// 根据 kid 获取对应的公钥
			publicKey, err := v.jwks.GetPublicKey(kid)
			if err != nil {
				return nil, err
			}

			return publicKey, nil
		},
			jwt.WithIssuer(v.issuer),
			jwt.WithAudience(v.audience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt())

		if err != nil || !token.Valid {
			log.Printf("%v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// 提取 claims 并进行额外验证
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// 验证 token 类型 (typ)
			if typ, exists := claims["typ"]; exists {
				if typ != "Bearer" {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token type"})
					return
				}
			}

			// 验证 scope
			if len(requiredScopes) > 0 {
				if !v.hasRequiredScopes(claims, requiredScopes) {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient scope"})
					return
				}
			}

			c.Set("user_id", claims["sub"])
			c.Set("email", claims["email"])
		}

		c.Next()
	}
}

func (v *JWTValidator) hasRequiredScopes(claims jwt.MapClaims, requiredScopes []string) bool {
	scopeStr, ok := claims["scope"].(string)
	if !ok {
		return false
	}

	userScopes := strings.Fields(scopeStr)
	for _, required := range requiredScopes {
		found := false
		for _, userScope := range userScopes {
			if userScope == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
