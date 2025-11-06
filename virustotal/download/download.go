package download

import (
	"bufio"
	"compress/bzip2"
	"fmt"
	"io"

	"log"
	"net/http"
	"time"
)

var (
	Client     HTTPClient = &http.Client{}
	MaxBufSize            = 30 * 1024 * 1024
	//MaxRecSize = 2000000
)

// HTTPClient interface to allow simpler test mocking.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Downloader provides an abstraction to access feed records from different endpoints.
type Downloader interface {
	// Fetch downloads any waiting batches of records and writes them to chan.
	// If backup is non-nil a compressed copy will be uploaded to that endpoint.
	// Channel ch will be closed when complete.
	// Set limit to -1 for no limit to number of requests/limit to download.
	Fetch(ch chan []byte, limit int)
}

// V3Downloader is for retrieving feeds via the V3 API.
type V3Downloader struct {
	url    string
	apikey string
	state  *State
	// frequency time.Duration
	lag    time.Duration
	format string
}

// NewDownloader creates a new Metadata Downloader instance with the supplied configuration.
func NewDownloader(statePath, url, apikey string) (Downloader, error) {
	// VTAPI V3 - minutely only
	// Currently goes back up to 3 days, up to 1 week history exists.
	state, err := NewState(statePath, time.Hour*72)
	if err != nil {
		return nil, err
	}
	return &V3Downloader{
		url:    fmt.Sprintf("%s/api/v3/feeds/files/", url),
		apikey: apikey,
		state:  &state,
		lag:    time.Hour,      // documented in api docs
		format: "200601021504", // YYYYMMDDHHmm
	}, nil
}

// NextMetadataPackage finds the next virustotal metadata package to obtain
func NextMetadataPackage(now time.Time, lag time.Duration, state *State) time.Time {
	// assume local clock is well synced?
	latest := now.UTC().Add(lag * -1)
	t := state.Next(time.Minute)
	if t.After(latest) {
		log.Printf("Package is too recent, need to wait til %s", t.Add(lag))
		return time.Time{}
	}
	return t
}

// ExtractJsonRecords pushes json lines to the channel
func ExtractJsonRecords(r io.Reader, ch chan []byte) error {
	s := bufio.NewScanner(r)
	buf := make([]byte, 0, MaxBufSize)
	s.Buffer(buf, MaxBufSize)
	for s.Scan() {
		ch <- s.Bytes()
	}
	if s.Err() != nil {
		return s.Err()
	}
	return nil
}

/*Common fetch functionality that returns true if successful or false if a 404 occurred.*/
func fetchCommon(ch chan []byte, req *http.Request, consecutive404 int) bool {
	resp, err := Client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// accept that we might be missing single 1 minutely bundle
		if consecutive404 > 0 {
			panic("too many 404 failures in a row")
		}
		return false
	} else if resp.StatusCode != 200 {
		// non 404 error
		body, _ := io.ReadAll(resp.Body)
		msg := fmt.Sprintf("Unexpected HTTP status returned: %d, request was %s\n", resp.StatusCode, req.URL)
		panic(msg + string(body))
	}
	bz := bzip2.NewReader(resp.Body)

	err = ExtractJsonRecords(bz, ch)
	if err != nil {
		log.Panicf("Failed to extract json records from V3 API: %v", err)
	}

	return true
}

func (d *V3Downloader) Fetch(ch chan []byte, limit int) {
	count := 0
	consecutive404 := 0
	defer close(ch)
	for {
		if limit > 0 && count >= limit {
			return
		}
		pkg := NextMetadataPackage(time.Now(), d.lag, d.state)
		if pkg.IsZero() {
			log.Println("Caught up to latest available package.. exiting")
			return
		}
		url := d.url + pkg.Format(d.format)
		log.Printf("Making request to: %s", url)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			panic(err)
		}
		req.Header.Set("x-apikey", d.apikey)

		// Common V3 fetch functionality
		if fetchCommon(ch, req, consecutive404) {
			count++
			consecutive404 = 0
		} else {
			consecutive404 += 1
		}

		err = d.state.Update(pkg)
		if err != nil {
			log.Panicf("Failed to update state with error %v", err)
		}
	}
}
