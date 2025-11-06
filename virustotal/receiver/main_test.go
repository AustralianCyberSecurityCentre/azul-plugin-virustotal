package receiver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
)

var server *httptest.Server
var respCode int = 200
var respBody []byte = []byte{}
var lastReqBody []byte = []byte{}

func responser(rw http.ResponseWriter, req *http.Request) {
	var err error
	lastReqBody, err = io.ReadAll(req.Body)
	if err != nil {
		rw.WriteHeader(500)
		_, err := rw.Write([]byte("bad body"))
		if err != nil {
			panic(err)
		}
		return
	}
	rw.WriteHeader(respCode)
	_, err = rw.Write(respBody)
	if err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	// Start a local HTTP server
	server = httptest.NewServer(http.HandlerFunc(responser))
	st.DispatcherEventsUrl = server.URL
	st.DispatcherDataUrl = server.URL
	ret := m.Run()
	// Close the server when test finishes
	server.Close()
	os.Exit(ret)
}
