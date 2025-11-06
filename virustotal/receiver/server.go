package receiver

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/goccy/go-json"
	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var maxLineBytes = 2000000 // dispatcher can only handle 2mb messages
var globalHeaderMap = map[string]string{}

type VTReceiveServer struct {
	read chan []byte
}

// endpoint to show server is working
func (srv *VTReceiveServer) getRoot(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var err error
	defer r.Body.Close()
	// Set global headers
	for header_key, header_val := range globalHeaderMap {
		w.Header().Set(header_key, header_val)
	}
	w.Header().Add("Content-Type", "text/plain")
	_, err = w.Write([]byte("hi this is the vtload server, please leave\n"))
	if err != nil {
		log.Printf("failed to write response %v", err)
	}
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("reading input failed with %v\n", err)
	w.WriteHeader(500)
	_, err = fmt.Fprintf(w, "reading input failed with %v\ndid you supply valid jsonlines?\n", err)
	if err != nil {
		log.Printf("failed to write response %v", err)
	}
}

// endpoint for posting virustotal metadata as jsonlines to server
func (srv *VTReceiveServer) postVirustotalData(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var err error
	defer r.Body.Close()
	// Set global headers
	for header_key, header_val := range globalHeaderMap {
		w.Header().Set(header_key, header_val)
	}
	w.Header().Add("Content-Type", "text/plain")

	// must be jsonlines
	log.Printf("%v", r.Header)
	if r.Header.Get("Content-Type") != "application/jsonlines" {
		w.WriteHeader(400)
		_, err = w.Write([]byte("'Content-Type: application/jsonlines' only"))
		if err != nil {
			log.Printf("failed to write response %v", err)
		}
		return
	}
	log.Printf("got ok looking /virustotal request")

	// read jsonlines line by line
	numEvents := 0
	reader := bufio.NewReaderSize(r.Body, maxLineBytes)
OUTER:
	for {
		line, isPrefix, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			internalError(w, err)
		}
		if isPrefix {
			log.Printf("skipping large line")
			// line too long, skip to end of line
			for {
				_, isPrefix, err := reader.ReadLine()
				if err == io.EOF {
					break OUTER
				} else if err != nil {
					internalError(w, err)
				}
				if !isPrefix {
					break
				}
			}
			continue
		}
		numEvents++
		srv.read <- line
	}

	fmt.Printf("read %d records", numEvents)
	_, err = fmt.Fprintf(w, "read %d records\n", numEvents)
	if err != nil {
		log.Printf("failed to write response %v", err)
	}
}

func makeServer(read chan []byte) *httprouter.Router {
	srv := VTReceiveServer{read: read}
	router := httprouter.New()

	headers := os.Getenv("PLUGIN_HEADERS")

	log.Printf("Headers from Env: %s", headers)
	if len(headers) > 0 {
		err := json.Unmarshal([]byte(headers), &globalHeaderMap)
		if err != nil {
			log.Fatalf("Failed to parse the headers %s into a map, with error %v", headers, err)
		}
		for header_key, header_val := range globalHeaderMap {
			log.Printf("HEADER %s: %s", header_key, header_val)
		}
	}
	router.GET("/", srv.getRoot)
	router.POST("/virustotal", srv.postVirustotalData)
	router.Handler(http.MethodGet, "/metrics", promhttp.Handler())
	return router
}

func RunServer(ch chan []byte) {
	defer close(ch)
	log.Fatal(http.ListenAndServe(":8854", makeServer(ch)))
}
