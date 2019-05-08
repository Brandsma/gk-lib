package token

import (
	"github.com/dgrijalva/jwt-go"

	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/Brandsma/gk-lib/handler"

	uuid "github.com/gofrs/uuid"
)

type signinResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// Claims defines what will be stored in a JWT access token
type Claims struct {
	ProgramVersion string `json:"programVersion"`
	UserAgent      string `json:"userAgent"`
	jwt.StandardClaims
}

// RefreshToken defines what will be stored in the database of the RefreshToken
type RefreshToken struct {
	UserID             string    `bson:"userId"`
	RefreshTokenString string    `bson:"refreshTokenString"`
	Expire             time.Time `bson:"expirationTime"`
	Valid              bool      `bson:"valid"`
}

// RefreshClaims defines what will be in the JWT refresh token
type RefreshClaims struct {
	UserID        string `json:"userId"`
	Version       string `json:"version"`
	RemoteAddress string `json:"remoteAddress"`
	UserAgent     string `json:"userAgent"`
	jwt.StandardClaims
}

func createClaim(userID string, expirationTime time.Time, tokenID string, uAgent string) *Claims {
	// TODO: Add more checking features
	return &Claims{
		ProgramVersion: os.Getenv("APP_VERSION"),
		UserAgent:      uAgent,
		StandardClaims: jwt.StandardClaims{
			Subject:   userID,
			ExpiresAt: expirationTime.Unix(),
			Issuer:    os.Getenv("CLAIM_ISSUER"),
			IssuedAt:  time.Now().Unix(),
			Id:        tokenID,
		},
	}
}

func createRefreshClaim(refreshTokenID string, refreshTokenExp time.Time, uID string, r *http.Request) *RefreshClaims {
	// TODO: Add more checking features
	return &RefreshClaims{
		UserID:        uID,
		Version:       os.Getenv("APP_VERSION"),
		RemoteAddress: r.RemoteAddr,
		UserAgent:     r.Header.Get("User-Agent"),
		StandardClaims: jwt.StandardClaims{
			Id:        refreshTokenID,
			Issuer:    os.Getenv("CLAIM_ISSUER"),
			ExpiresAt: refreshTokenExp.Unix(),
		},
	}
}

// SetToken sets both an access token and refresh token to the cookies
// An access token is base64 URL encoded
// A refresh token is encoded in a gorilla session
// After this it redirects to the given redirect url (both relative and absolute)
func SetToken(w http.ResponseWriter, r *http.Request, db *mgo.Session, userID string) *handler.AppError {
	// Construct a response to a succesful signin
	var sr signinResponse

	// Create Access Token
	access, err := createAccessToken(userID, r.Header.Get("User-Agent"))
	if err != nil {
		return handler.AppErrorf(206, err, "Setting the access token failed")
	}
	sr.AccessToken = access

	// Create Refresh Token
	refresh, err := createRefreshToken(w, r, userID, db)
	if err != nil {
		return handler.AppErrorf(206, err, "Setting the refresh token failed")
	}
	sr.RefreshToken = refresh

	// Marshal signin response
	srJSON, err := json.Marshal(sr)
	if err != nil {
		return handler.AppErrorf(500, err, "Could not marshal signin response")
	}

	// Respond
	w.Header().Set("Content-Type", "application/json")
	w.Write(srJSON)
	return nil
}

func createAccessToken(userID string, uAgent string) (string, error) {
	tokenID := uuid.Must(uuid.NewV4()).String()
	expireTime, err := strconv.Atoi(os.Getenv("EXPIRE_TIME"))
	if err != nil {
		return "", err
	}
	expirationTime := time.Now().Add(time.Duration(expireTime) * time.Second)

	claims := createClaim(userID, expirationTime, tokenID, uAgent)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := accessToken.SignedString([]byte(os.Getenv("JWT_SIGNING_SECRET")))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func createRefreshToken(w http.ResponseWriter, r *http.Request, userID string, db *mgo.Session) (string, error) {
	refreshExpireTime, err := strconv.Atoi(os.Getenv("REFRESH_EXPIRE_TIME"))
	if err != nil {
		return "", err
	}
	refreshTokenExp := time.Now().Add(time.Duration(refreshExpireTime) * time.Second)
	refreshTokenID := uuid.Must(uuid.NewV4()).String()

	refreshClaims := createRefreshClaim(refreshTokenID, refreshTokenExp, userID, r)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("REFRESH_SIGNING_SECRET")))
	if err != nil {
		return "", err
	}

	// Insert refresh token into database
	rt := &RefreshToken{
		UserID:             userID,
		RefreshTokenString: refreshTokenString,
		Expire:             refreshTokenExp,
		Valid:              true,
	}

	rc := db.DB(os.Getenv("DATABASE_NAME")).C(os.Getenv("REFRESH_COLLECTION"))
	// Remove any old refresh tokens from the database
	if err := rc.Remove(bson.M{"userId": userID}); err != nil && err.Error() != "not found" {
		return "", err
	}
	// Insert new refresh token
	if err := rc.Insert(&rt); err != nil {
		return "", err
	}

	return refreshTokenString, nil
}
