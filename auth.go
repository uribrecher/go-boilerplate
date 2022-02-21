package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
)

const (
	claimsUserIDField  = "user_id"
	claimsMailVerified = "email_verified"

	authHeaderKey = "Authorization"
	bearerPrefix  = "Bearer "
	minBearerSize = len(bearerPrefix)
)

type EmailVerificationError struct {
	msg string
}

func (e EmailVerificationError) Error() string {
	return e.msg
}

// GetHS256JWTAuth returns a new token auth (`*jwt.JWTAuth`)
// with which one could verify or encode tokens
func GetHS256JWTAuth(signingKey *string) (*jwtauth.JWTAuth, error) {
	if signingKey == nil {
		return nil, errors.New("HS256 signing key must be provided")
	}
	return jwtauth.New("HS256", []byte(*signingKey), nil), nil
}

// GetRS256JWTAuth returns a new token verifier (`*jwt.JWTAuth`)
// if PrivateKeyRS256String is nil then only verification is possible
// if both inputs are nil then no Auth will be initialized
func GetRS256JWTAuth(PublicKeyRS256String, PrivateKeyRS256String *string) (auth *jwtauth.JWTAuth, err error) {
	if PublicKeyRS256String != nil {
		var privateKey *rsa.PrivateKey

		// PrivateKeyRS256String is optional
		if PrivateKeyRS256String != nil {
			privateKeyBlock, _ := pem.Decode([]byte(*PrivateKeyRS256String))
			if privateKeyBlock == nil {
				return nil, errors.New("unable to decode RS256 private key")
			}
			privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
			if err != nil {
				return nil, err
			}
		}

		publicKeyBlock, _ := pem.Decode([]byte(*PublicKeyRS256String))
		if publicKeyBlock == nil {
			return nil, errors.New("unable to decode RS256 public key")
		}
		publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
		if err != nil {
			return nil, err
		}

		return jwtauth.New("RS256", privateKey, publicKey), nil
	}
	//no keys provided
	return nil, nil
}

// EncodeToken encodes a JWT token using a `*jwtauth.JWTAuth`.
// `userID` is the user ID to which the token is encoded.
// `expiryIn` is a `time.Duration` duration after which the token will be expired.
func EncodeToken(tokenAuth *jwtauth.JWTAuth, userID string, expiryIn time.Duration) (string, error) {
	mapClaims := jwt.MapClaims{claimsUserIDField: userID}
	jwtauth.SetExpiryIn(mapClaims, expiryIn)
	_, tokenString, err := tokenAuth.Encode(mapClaims)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// CreateJWTVerifier creates a middleware using the provided authenticators
func CreateJWTVerifier(rs256Auth *jwtauth.JWTAuth, requireMailVerification bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			l := logger.GetFromContext(ctx)
			// get the prefix word of the authorization header:
			authHeader := r.Header.Get(authHeaderKey)
			if rs256Auth == nil {
				l.Error().Msg("RS256JWTAuth must be initialized")
				httputil.EncodeErrorResponse(w, http.StatusInternalServerError, errors.New("user cannot be authenticated"))
				return
			}
			// todo: check issuer from claims
			newCtx := context.WithValue(ctx, httputil.AuthTypeCtxKey, httputil.Auth0)

			err := checkAuth0MailVerification(rs256Auth, authHeader, requireMailVerification)
			if err != nil {
				if err, ok := err.(*jwt.ValidationError); ok {
					l.Error().Err(err).Msg("token validation error")
					httputil.EncodeErrorResponse(w, http.StatusUnauthorized, errors.New("unable to parse token"))
					return
				}
				if err, ok := err.(EmailVerificationError); ok {
					l.Error().Err(err).Msg("email verification error")
					httputil.EncodeErrorResponse(w, http.StatusUnauthorized, err)
					return
				}

				l.Error().Err(err).Msg("checkAuth0MailVerification failed")
				httputil.EncodeErrorResponse(w, http.StatusUnauthorized, errors.New("unable to parse jwt token and claims"))
				return
			}

			jwtauth.Verifier(rs256Auth)(next).ServeHTTP(w, r.WithContext(newCtx))
			return
		})
	}
}

// checkAuth0MailVerification will verify that "email_verified" = true is part the jwt claims
// mail verification is required only if HTTP.REQUIRE_MAIL_VERIFICATION configured to be true
func checkAuth0MailVerification(auth *jwtauth.JWTAuth, bearer string, requireMailVerification bool) error {
	if !requireMailVerification {
		return nil
	}

	if len(bearer) < minBearerSize {
		return fmt.Errorf("internal error: JWT should be prefixed by %s", bearerPrefix)
	}

	token, err := auth.Decode(bearer[minBearerSize:])
	if err != nil {
		return err
	}

	var claims jwt.MapClaims
	if tokenClaims, ok := token.Claims.(jwt.MapClaims); ok {
		claims = tokenClaims
	} else {
		return errors.New("unable to get jwt claims")
	}

	if isVerified, ok := claims[claimsMailVerified].(bool); ok && isVerified {
		return nil
	} else {
		return EmailVerificationError{"email_verified should be set to 'true' as part of the claims"}
	}
}

// CreateGetJwtUser will create a middleware that
// 1) make sure the token is verified
// 2) extracting the user id from the claims map
func CreateGetJwtUser() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			l := logger.GetFromContext(ctx)
			token, claims, err := jwtauth.FromContext(ctx)

			if err != nil {
				l.Error().Err(err).Msg("token error")
				if err.Error() == "crypto/rsa: verification error" {
					httputil.EncodeErrorResponse(w, http.StatusUnauthorized, errors.New("token verification error"))
					return
				}
				httputil.EncodeErrorResponse(w, http.StatusUnauthorized, errors.New("error parsing token"))
				return
			}

			if token == nil || !token.Valid {
				l.Error().Msg("user cannot be authenticated: invalid token")
				httputil.EncodeErrorResponse(w, http.StatusUnauthorized, errors.New("invalid token"))
				return
			}

			var u *User
			var c int

			switch authType := ctx.Value(httputil.AuthTypeCtxKey); authType {
			case httputil.Auth0:
				u, err, c = getUserFromAuth0Token(claims)

			default:
				httputil.EncodeErrorResponse(w, http.StatusInternalServerError, errors.New("unknown authentication method"))
				return
			}
			if err != nil {
				l.Error().Err(err).Msgf("get user data error")
				httputil.EncodeErrorResponse(w, c, err)
				return
			}

			l.Debug().Msg("token is authenticated and user data is fetched - attaching user to context")
			newCtx := context.WithValue(ctx, httputil.UserCtxKey, u)
			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}

// Auth0 specific handler
// claims must contain email, sub
func getUserFromAuth0Token(claims jwt.MapClaims) (u *User, err error, httpErrorCode int) {
	email, ok := claims["email"].(string)
	if !ok {
		return nil, errors.New("cannot get email from auth0 jwt token claims"), http.StatusBadRequest
	}
	emailVerified, ok := claims["email_verified"].(bool)
	if !ok {
		return nil, errors.New("cannot get 'email_verified' from auth0 jwt token claims"), http.StatusBadRequest
	}
	id, ok := claims["sub"].(string)
	if !ok || id == "" {
		return nil, errors.New("cannot get subject id from auth0 jwt token claims"), http.StatusBadRequest
	}
	u = &User{
		ID:           id,
		Mail:         email,
		MailVerified: emailVerified,
	}
	return u, nil, http.StatusOK
}

func computeHmac256(message string, secret string) (string, error) {
	key := []byte(secret)

	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil)), err
}
