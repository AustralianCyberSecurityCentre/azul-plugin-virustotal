package batch

import (
	"errors"
	"log"
	"sync"
	"time"

	bedclient "github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/client"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
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

// post a list of events to dispatcher
func (batcher *Batcher) postBatch(evs []*events.BinaryEvent) int {
	bulk := events.BulkBinaryEvent{Events: evs}
	resp, err := batcher.dpclient.PostEvents(&bulk, &bedclient.PublishBytesOptions{Sync: true})
	if err != nil {
		var statusError *bedclient.HttpError
		if errors.As(err, &statusError) {
			// Status error if all the submission is filtered or another 425 error
			if statusError.StatusCode == 425 {
				log.Printf("Warning skipping publish of events because %s.", statusError.Body)
				return len(bulk.Events)
			}
		}
		// total failure when submitting
		log.Printf("unrecoverable error publishing %v batch events: %v", len(evs), err)
		panic(err)
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
