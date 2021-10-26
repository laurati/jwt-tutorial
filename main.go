package main

import (
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.POST("/login", Login)
	router.GET("/home", Home)
	router.POST("/refresh", Refresh)

	// start the server on port 8080
	router.Run()
}
