package auth

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"os"
	"time"
)

// CreateToken generates a JSON Web Token (JWT) using the provided user token.
// It takes the user token as input and returns the generated token string and an error, if any.
// The function uses the secret key retrieved from the environment variable SECRET_KEY for signing the token.
// The token is set to expire after 24 hours from the current time.
// If there is an error during token creation, an empty string and the error are returned.
//
// Example usage:
// tokenString, err := CreateToken("user123")
//
//	if err != nil {
//	    fmt.Println("Error creating token:", err)
//	} else {
//
//	    fmt.Println("Token:", tokenString)
//	}
func CreateToken(usertkn string) (string, error) {
	var secretKey = []byte(os.Getenv("SECRET_KEY"))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"usertkn": usertkn,
			"exp":     time.Now().Add(time.Hour * 24).Unix(),
		})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// VerifyToken verifies the authenticity of a JSON Web Token (JWT) using the provided token string.
// It takes the token string as input and returns the user token and an error, if any.
// The function uses the secret key retrieved from the environment variable SECRET_KEY for token verification.
// If the token cannot be parsed or is invalid, an error is returned.
// If the token is valid, the user token is extracted from the token claims and returned.
//
// Example usage:
// usertkn, err := VerifyToken(tokenString)
//
//	if err != nil {
//	    fmt.Println("Error verifying token:", err)
//	} else {
//
//	    fmt.Println("User Token:", usertkn)
//	}
func VerifyToken(tokenString string) (usertkn string, err error) {
	var secretKey = []byte(os.Getenv("SECRET_KEY"))
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return usertkn, err
	}

	if !token.Valid {
		return usertkn, fmt.Errorf("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)

	usertkn = claims["usertkn"].(string)

	return usertkn, nil
}
