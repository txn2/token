package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"

	"github.com/txn2/token"
	"go.uber.org/zap"
)

var (
	ipEnv   = getEnv("IP", "127.0.0.1")
	portEnv = getEnv("PORT", "8080")
	keyEnv  = getEnv("KEY", "somekey")
	expEnv  = getEnv("EXP", "1")
)

func main() {

	expEnvInt, err := strconv.Atoi(expEnv)
	if err != nil {
		fmt.Printf("Expiration must be minutes in integer form: %s\n", err.Error())
		os.Exit(1)
	}

	var (
		ip   = flag.String("ip", ipEnv, "Server IP address to bind to.")
		port = flag.String("port", portEnv, "Server port.")
		key  = flag.String("key", keyEnv, "Token signing key.")
		exp  = flag.Int("exp", expEnvInt, "Expiration in minutes.")
	)

	flag.Parse()

	zapCfg := zap.NewDevelopmentConfig()
	gin.SetMode(gin.DebugMode)

	logger, err := zapCfg.Build()
	if err != nil {
		fmt.Printf("Can not build logger: %s\n", err.Error())
		os.Exit(1)
	}

	logger.Info("Starting Token Server",
		zap.String("type", "ack_startup"),
		zap.String("port", *port),
		zap.String("ip", *ip),
	)

	// gin router
	r := gin.New()

	// gin zap logger middleware
	r.Use(ginzap.Ginzap(logger, time.RFC3339, true))

	// token middleware
	jwt := token.NewJwt(token.JwtCfg{
		Exp:    *exp,
		EncKey: []byte(*key),
	})

	r.Use(jwt.GinHandler())

	// routes
	r.POST("/tokenize", func(c *gin.Context) {

		data := make(map[string]interface{})

		rs, err := c.GetRawData()
		if err != nil {
			err := c.AbortWithError(500, err)
			logger.Error("GetRawData", zap.Error(err))
			return
		}

		err = json.Unmarshal(rs, &data)
		if err != nil {
			err = c.AbortWithError(500, err)
			logger.Error("json.Unmarshal", zap.Error(err))
			return
		}

		tkn, err := jwt.GetToken(data)
		if err != nil {
			err = c.AbortWithError(500, err)
			logger.Error("jwt.GetToken", zap.Error(err))
			return
		}

		if c.Query("raw") == "true" {
			c.Data(200, "text/plain", []byte(tkn))
			return
		}

		c.JSON(200, gin.H{"token": tkn})
	})

	// validate a token
	r.GET("/validate", func(c *gin.Context) {
		tokI, ok := c.Get("Tok")
		if !ok {
			err = c.AbortWithError(500, fmt.Errorf("unable to get token"))
			logger.Error("Tok", zap.Error(err))
			return
		}

		tok := tokI.(*token.Tok)

		c.JSON(200, tok)
	})

	// serve

	s := &http.Server{
		Addr:           *ip + ":" + *port,
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	err = s.ListenAndServe()
	if err != nil {
		fmt.Printf("Can not run server: %s\n", err.Error())
		os.Exit(1)
	}
}

// getEnv gets an environment variable or sets a default if
// one does not exist.
func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}

	return value
}
