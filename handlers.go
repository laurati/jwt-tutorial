package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

// Create the JWT key used to create the signature
var jwtKey = []byte("secret_key")

//there are only two valid users in our application
//The login route will take the users credentials and log them in.
//For simplification, we’re storing the users information as an in-memory map in our code
var users = map[string]string{
	"users1": "password1",
	"users2": "password2",
}

// Create a struct to read the username and password from the request body
type Credentials struct {
	Username string `json: "username"`
	Password string `json: "password"`
}

// Create a struct that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	Username string `json: "username"`
	jwt.StandardClaims
}

// Create the Signin handler
func Login(c *gin.Context) {
	var credentials Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(c.Request.Body).Decode(&credentials)
	if err != nil {
		c.String(http.StatusBadRequest, "")
		return
	}

	// Get the expected password from our in memory map
	expectedPassword, ok := users[credentials.Username]

	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	if !ok || expectedPassword != credentials.Password {
		c.String(http.StatusUnauthorized, "")
		return
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(time.Minute * 5)

	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		c.String(http.StatusInternalServerError, "")
		return
	}

	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

}

func Home(c *gin.Context) {

	// We can obtain the session token from the requests cookies, which come with every request
	cookie, err := c.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			c.IndentedJSON(http.StatusUnauthorized, nil)
			return
		}
		// For any other type of error, return a bad request status
		c.IndentedJSON(http.StatusBadRequest, nil)
		return
	}

	// Get the JWT string from the cookie
	//tknStr := cookie.Value
	tknStr := cookie

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims,
		func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.IndentedJSON(http.StatusUnauthorized, nil)
			return
		}
		c.IndentedJSON(http.StatusBadRequest, nil)
		return
	}
	if !tkn.Valid {
		c.IndentedJSON(http.StatusUnauthorized, nil)
		return
	}

	// Finally, return the welcome message to the user, along with their
	// username given in the token
	c.AbortWithStatusJSON(http.StatusAccepted, (fmt.Sprintf("Welcome %s!", claims.Username)))
}

func Refresh(c *gin.Context) {

	// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
	co, err := c.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			c.IndentedJSON(http.StatusUnauthorized, nil)
			return
		}
		c.IndentedJSON(http.StatusBadRequest, nil)
		return
	}
	tknStr := co
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.IndentedJSON(http.StatusUnauthorized, nil)
			return
		}
		c.IndentedJSON(http.StatusBadRequest, nil)
		return
	}
	if !tkn.Valid {
		c.IndentedJSON(http.StatusUnauthorized, nil)
		return
	}
	// (END) The code up-till this point is the same as the first part of the `Welcome` route

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		c.IndentedJSON(http.StatusBadRequest, nil)
		return
	}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, nil)
		return
	}

	// Set the new token as the users `token` cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

}
