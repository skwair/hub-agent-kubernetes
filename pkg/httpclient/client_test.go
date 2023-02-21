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

package httpclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newHTTPClient_WithProxyEnvVars(t *testing.T) {
	testProxyServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := rw.Write([]byte(`PROXIED`))
		require.NoError(t, err)
	}))
	defer testProxyServer.Close()

	os.Clearenv()

	t.Setenv("HTTP_PROXY", testProxyServer.URL)

	client, err := NewWithLogger(Config{}, zerolog.New(io.Discard))
	require.NoError(t, err)

	resp, err := client.Get("http://foo.bar")
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, []byte(`PROXIED`), body)
}
