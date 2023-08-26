package main

import (
	"github.com/3JoB/teler-waf"
	"github.com/gin-gonic/gin"
)

func main() {
	telerMiddleware := teler.New()

	telerFunc := func() gin.HandlerFunc {
		return func(c *gin.Context) {
			err := telerMiddleware.Analyze(c.Writer, c.Request)

			// If there was an error, do not continue.
			if err != nil {
				c.Abort()
				return
			}

			// Avoid header rewrite if response is a redirection.
			if status := c.Writer.Status(); status > 300 && status < 399 {
				c.Abort()
			}
		}
	}()

	router := gin.Default()
	router.Use(telerFunc)

	router.GET("/", func(c *gin.Context) {
		c.String(200, "hello world")
	})

	router.Run("127.0.0.1:3000")
}
