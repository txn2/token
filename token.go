package token

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v4"
)

func NewJwt(cfg JwtCfg) *Jwt {
	return &Jwt{
		Cfg: cfg,
	}
}

// JwtCfg defines a token generator object
type JwtCfg struct {
	EncKey []byte

	// Expiration minutes
	Exp int

	Claims interface{}
}

type Jwt struct {
	Cfg JwtCfg
}

// Tok is a token
type Tok struct {
	Claims jwtlib.MapClaims
	Valid  bool
	Err    error
}

// GetToken generated a HS256 token from an object
func (jwt *Jwt) GetToken(v interface{}) (string, error) {
	// make a token
	token := jwtlib.New(jwtlib.GetSigningMethod("HS256"))

	time.Local = time.UTC
	token.Claims = jwtlib.MapClaims{
		"data": v,
		"exp":  time.Now().Unix() + (int64(jwt.Cfg.Exp) * 60),
	}
	tokenString, err := token.SignedString(jwt.Cfg.EncKey)

	return tokenString, err
}

// GinHandler is a middleware for Gin-gonic
func (jwt *Jwt) GinHandler() gin.HandlerFunc {
	return func(c *gin.Context) {

		claims, err := jwt.GinParse(c)
		tok := &Tok{
			Claims: claims,
			Valid:  true,
			Err:    err,
		}
		if err != nil {
			tok.Err = err
			tok.Valid = false
		}

		c.Set("Tok", tok)
	}
}

// GinParse parses a gin.Context
func (jwt *Jwt) GinParse(c *gin.Context) (map[string]interface{}, error) {

	var (
		claims jwtlib.MapClaims
		tokStr = ""
	)

	authHeader := strings.Split(c.GetHeader("Authorization"), " ")
	if len(authHeader) > 1 && authHeader[0] == "Bearer" {
		tokStr = authHeader[1]
	}

	if len(tokStr) > 0 {
		token, err := jwtlib.Parse(tokStr, func(token *jwtlib.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwtlib.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return jwt.Cfg.EncKey, nil
		})

		if err != nil {
			return claims, err
		}

		if claims, ok := token.Claims.(jwtlib.MapClaims); ok && token.Valid {
			return claims, nil
		}

	}

	return claims, errors.New("invalid token")
}
