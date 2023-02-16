/*
Copyright (C) 2022-2023 Traefik Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package oauthintro

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// TokenSource describes where to find a token in an HTTP request.
type TokenSource struct {
	Header           string `json:"header,omitempty"`
	HeaderAuthScheme string `json:"headerAuthScheme,omitempty"`
	Query            string `json:"query,omitempty"`
	Cookie           string `json:"cookie,omitempty"`
}

func extractToken(req *http.Request, src TokenSource) (string, error) {
	token, err := getTokenFromHeader(req.Header, src.Header, src.HeaderAuthScheme)
	if err != nil {
		return "", fmt.Errorf("extract token from header: %w", err)
	}
	if token != "" {
		return token, nil
	}

	token, err = getTokenFromQuery(req.Header, src.Query)
	if err != nil {
		return "", fmt.Errorf("extract token from query: %w", err)
	}
	if token != "" {
		return token, nil
	}

	if src.Cookie != "" {
		if cookie, _ := req.Cookie(src.Cookie); cookie != nil && cookie.Value != "" {
			return cookie.Value, nil
		}
	}

	return "", errors.New("missing token source")
}

func getTokenFromHeader(header http.Header, headerName, headerAuthScheme string) (string, error) {
	if headerName == "" {
		return "", nil
	}

	token := header.Get(headerName)
	if token == "" {
		return "", nil
	}

	if headerName == "Authorization" && headerAuthScheme != "" {
		parts := strings.SplitN(token, " ", 2)
		if len(parts) < 2 || parts[0] != headerAuthScheme {
			return "", errors.New("invalid auth scheme")
		}

		return strings.TrimSpace(parts[1]), nil
	}

	return token, nil
}

func getTokenFromQuery(header http.Header, tokenName string) (string, error) {
	if tokenName == "" {
		return "", nil
	}

	if uri := originalURI(header); uri != "" {
		parsedURI, err := url.Parse(uri)
		if err != nil {
			return "", err
		}

		if qry := parsedURI.Query().Get(tokenName); qry != "" {
			return qry, nil
		}
	}

	return "", nil
}

// originalURI gets the original URI that was sent to the ingress controller, regardless of its type.
// It currently supports Traefik (X-Forwarded-Uri) and Nginx Community (X-Original-Url).
func originalURI(hdr http.Header) string {
	if xfu := hdr.Get("X-Forwarded-Uri"); xfu != "" {
		return xfu
	}

	return hdr.Get("X-Original-Url")
}
