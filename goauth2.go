package goauth2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var client = http.Client{}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	ExpiresIn    string `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

type idToken struct {
	Iss           string `json:"iss"`
	AtHash        string `json:"at_hash"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
	Azp           string `json:"azp"`
	Email         string `json:"email"`
	Aud           string `json:"aud"`
	Iat           int    `json:"iat"`
	Exp           int    `json:"exp"`
}

func VerifyEmail(clientId, clientSecret, code string, redirectUrl *url.URL) (email string, ok bool, err error) {
	q := url.Values{}
	q.Add("code", code)
	q.Add("client_id", clientId)
	q.Add("client_secret", clientSecret)
	q.Add("redirect_uri", redirectUrl.String())
	q.Add("grant_type", "authorization_code")

	resp, err := client.Post("https://www.googleapis.com/oauth2/v3/token", "application/x-www-form-urlencoded", bytes.NewBufferString(q.Encode()))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	validateResult := &tokenResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&validateResult); err != nil {
		return
	}

	parts := strings.Split(validateResult.IdToken, ".")
	encodedIdData := parts[1]

	for len(encodedIdData)%4 != 0 {
		encodedIdData += "="
	}

	idBytes, err := base64.StdEncoding.DecodeString(encodedIdData)
	if err != nil {
		err = fmt.Errorf("Unable to decode %#v from base64: %v", encodedIdData, err)
		return
	}

	token := &idToken{}
	if err = json.Unmarshal(idBytes, &token); err != nil {
		return
	}

	email, ok = token.Email, token.EmailVerified

	return
}

func GetAuthURL(clientId, nonce string, returnTo *url.URL) (result *url.URL, err error) {
	q := url.Values{}
	q.Add("scope", "email")
	q.Add("state", nonce)
	q.Add("redirect_uri", returnTo.String())
	q.Add("response_type", "code")
	q.Add("client_id", clientId)

	result, err = url.Parse(fmt.Sprintf("https://accounts.google.com/o/oauth2/auth?%v", q.Encode()))
	return
}
