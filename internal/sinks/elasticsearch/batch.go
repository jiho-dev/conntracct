package elasticsearch

import (
	"context"
	"strconv"

	elastic "github.com/olivere/elastic/v7"
	log "github.com/sirupsen/logrus"
)

// batch is a batch of events.
type batch []*event

// newBatch allocates a new InfluxDB point batch to the sink structure.
func (s *ElasticSink) newBatch() {
	// Allocate new batch and write it to the sink.
	s.batch = make(batch, 0, s.config.BatchSize)
	s.stats.SetBatchLength(0)
}

// addBatchEvent adds the given event to the current batch.
// If the operation causes the batch watermark to be reached,
// the batch is flushed. Do not call while holding batchMu.
func (s *ElasticSink) addBatchEvent(e *event) {

	s.batchMu.Lock()

	// Add the given point to the current batch.
	s.batch = append(s.batch, e)

	// Record the current batch length.
	batchLen := len(s.batch)
	s.stats.SetBatchLength(batchLen)

	// Flush the batch when the watermark is reached.
	if batchLen >= int(s.config.BatchSize) {
		s.flushBatch()
	}

	s.batchMu.Unlock()
}

// flushBatch sends the current batch to the send worker
// and allocates a new batch into the sink structure.
func (s *ElasticSink) flushBatch() {

	// Don't take action if the batch is empty.
	if len(s.batch) == 0 {
		return
	}

	// Non-blocking send on sendChan.
	select {
	case s.sendChan <- s.batch:
		s.stats.IncrBatchesQueued()
		s.stats.SetBatchQueueLength(len(s.sendChan))
	default:
		// Log a dropped batch if no receiver is ready.
		s.stats.IncrBatchDropped()
	}

	// Allocate a new batch into the sink.
	s.newBatch()
}

// sendBatch sends the given batch to the configured elasticsearch
// backend in a single bulk transaction.
func (s *ElasticSink) sendBatch(b batch) {

	// Create an elastic bulk request.
	bulk := s.client.Bulk().Index(s.config.Database)

	// Create index requests for each event in the batch.
	reqs := make([]elastic.BulkableRequest, 0, len(b))
	for _, e := range b {
		s := elastic.NewScriptStored(scriptFlowUpsertName).Param("doc", e)
		reqs = append(reqs,
			elastic.NewBulkUpdateRequest().
				// Use ES as a latest value store, update the flow's document
				// with the latest counters on each incoming event.
				Id(strconv.FormatUint(uint64(e.FlowID), 10)).
				// In case the document doesn't exist yet, insert an empty
				// document so ES doesn't complain with a missing document
				// exception.
				Upsert(map[int]int{}).
				// Always run the update script, even when the document didn't
				// exist before the update request.
				ScriptedUpsert(true).
				Script(s),
		)
	}

	// Add all index requests to the bulk request.
	bulk.Add(reqs...)

	// Send the request.
	resp, err := bulk.Do(context.Background())
	if err != nil {
		// Increase dropped batch counter.
		s.stats.IncrBatchDropped()
		log.WithField("sink", s.config.Name).Error("error sending batch: ", err.Error())
		return
	}

	// Increase sent batch counter.
	s.stats.IncrBatchSent()

	// Check for requests that failed to index.
	failed := resp.Failed()
	if len(failed) != 0 {
		for _, f := range failed {
			// Increase the counter of events that failed to be indexed.
			s.stats.IncrBatchEventsFailed()
			log.WithField("sink", s.config.Name).
				WithField("type", f.Error.Type).WithField("status", f.Status).
				WithField("reason", f.Error.Reason).WithField("cause", f.Error.CausedBy).
				Error("error indexing event")
		}
	}
}
