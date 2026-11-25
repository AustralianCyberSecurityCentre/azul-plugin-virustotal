package batch

import (
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	bedclient "github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/client"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/events"
)

type Batcher struct {
	dpclient        *bedclient.Client
	SendWorkerCount int
	SendBatchSize   int
	MaxRecSize      int
}

func NewBatcher(dpclient *bedclient.Client) *Batcher {
	return &Batcher{
		dpclient:        dpclient,
		SendWorkerCount: 1,
		SendBatchSize:   50,
		MaxRecSize:      2000000,
	}
}

// IsAgedOffRejection identifies the specific Dispatcher response indicating that
// every submitted event is outside the source retention window. It must not
// suppress other HTTP 425 responses or transient publishing failures.
func IsAgedOffRejection(err error) bool {
	var statusError *bedclient.HttpError
	if !errors.As(err, &statusError) {
		return false
	}
	return isAgedOffResponse(statusError.StatusCode, []byte(statusError.Body))
}

func isAgedOffResponse(statusCode int, body []byte) bool {
	if statusCode != 425 {
		return false
	}
	var payload struct {
		ErrorEnum string `json:"error_enum"`
	}
	return json.Unmarshal(body, &payload) == nil &&
		payload.ErrorEnum == "ErrorStringEnumAllEventsAgedOffImmediately"
}

// post a list of events to dispatcher
func (batcher *Batcher) postBatch(evs []*events.BinaryEvent) int {
	bulk := events.BulkBinaryEvent{Events: evs}
	resp, err := batcher.dpclient.PostEvents(&bulk, &bedclient.PublishBytesOptions{Sync: true})
	if err != nil {
		if IsAgedOffRejection(err) {
			log.Printf("Dispatcher intentionally aged off %d binary events (outside source retention); continuing", len(evs))
			return 0
		}
		log.Printf("failed publishing %d batch events: %v", len(evs), err)
		return len(evs)
	}
	return resp.TotalFailures
}

// send incoming messages to dispatcher and register number of errors encountered
func (batcher *Batcher) SendBulkBinaryEvents(msgs chan *events.BinaryEvent, numErrors chan int) *sync.WaitGroup {
	var wg sync.WaitGroup
	wg.Add(batcher.SendWorkerCount)
	for range batcher.SendWorkerCount {
		go func() {
			totalErr := 0
			defer wg.Done()
			evs := make([]*events.BinaryEvent, 0, batcher.SendBatchSize)
			count := 0
			var event *events.BinaryEvent
			for {
				select {
				case event = <-msgs:
				case <-time.After(60 * time.Second):
					if len(evs) > 0 {
						// Forced flush
						log.Println("no additional messages received, flush messages")
						totalErr += batcher.postBatch(evs)
						evs = evs[:0]
					}
					continue
				}
				if event == nil {
					break
				}
				// accumulate the message
				evs = append(evs, event)
				count++
				if count%batcher.SendBatchSize == 0 {
					totalErr += batcher.postBatch(evs)
					evs = evs[:0]
				}
			}
			// don't forget any residual
			if len(evs) > 0 {
				totalErr += batcher.postBatch(evs)
			}
			numErrors <- totalErr
		}()
	}
	return &wg
}
