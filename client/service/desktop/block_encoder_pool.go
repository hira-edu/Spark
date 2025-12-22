package desktop

import (
	"context"
	"image"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// BlockEncoderPool manages parallel block encoding workers.
// It distributes block encoding jobs across N workers to utilize
// multiple CPU cores, significantly reducing tile encoding latency.
//
// Architecture:
//   ┌─────────────┐      ┌─────────────┐
//   │   Worker 1  │──┐   │             │
//   ├─────────────┤  │   │             │
//   │   Worker 2  │──┼──▶│   Results   │──▶ Ordered output
//   ├─────────────┤  │   │   Channel   │
//   │   Worker N  │──┘   │             │
//   └─────────────┘      └─────────────┘
//
// Performance: With 4 workers on 8-core CPU, encoding parallelizes
// across cores, reducing frame encoding time by ~2-4x.
type BlockEncoderPool struct {
	workers int
	jobs    chan blockJob
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	// Statistics
	stats encoderPoolStats
}

// blockJob represents a single block encoding task.
type blockJob struct {
	img      *image.RGBA     // Source image (shared, read-only)
	srcRect  image.Rectangle // Source rect (image coordinates)
	outRect  image.Rectangle // Output rect (browser canvas coordinates)
	seqNum   int             // Sequence number for ordering
	resultCh chan<- blockResult
}

// blockResult holds the encoded block data.
type blockResult struct {
	data   []byte
	seqNum int
	err    error
}

// encoderPoolStats tracks pool performance metrics.
type encoderPoolStats struct {
	jobsSubmitted atomic.Uint64
	jobsCompleted atomic.Uint64
	encodingNs    atomic.Uint64 // Total encoding nanoseconds
}

// NewBlockEncoderPool creates a new pool with the specified worker count.
// If workers <= 0, defaults to 4 workers (balanced CPU utilization vs jitter).
// Note: Too many workers can cause CPU contention and frame jitter.
func NewBlockEncoderPool(workers int) *BlockEncoderPool {
	if workers <= 0 {
		// Use 4 workers as a balanced default - enough parallelism without
		// causing CPU contention that leads to frame jitter
		workers = 4
	}
	if workers < 2 {
		workers = 2
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &BlockEncoderPool{
		workers: workers,
		jobs:    make(chan blockJob, workers*4), // Buffer for burst handling
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start spawns worker goroutines.
func (p *BlockEncoderPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

// Stop gracefully shuts down all workers.
func (p *BlockEncoderPool) Stop() {
	p.cancel()
	p.wg.Wait()
	close(p.jobs)
}

// worker processes jobs from the queue.
func (p *BlockEncoderPool) worker() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return
			}
			p.processJob(job)
		}
	}
}

// processJob encodes a single block.
func (p *BlockEncoderPool) processJob(job blockJob) {
	// Encode the block using existing function
	blockData, codecType := getImageBlock(job.img, job.srcRect)

	// Add header with browser canvas coordinates
	blockData = makeImageBlock(blockData, job.outRect, codecType)

	p.stats.jobsCompleted.Add(1)

	// Send result back (non-blocking since result channel is buffered)
	select {
	case job.resultCh <- blockResult{data: blockData, seqNum: job.seqNum}:
	case <-p.ctx.Done():
	}
}

// EncodeBlocks encodes multiple blocks in parallel and returns them in order.
// This is the main entry point for parallel block encoding.
//
// Parameters:
//   - img: Source image (shared, read-only access)
//   - srcRects: Source rectangles (image coordinates)
//   - outRects: Output rectangles (browser canvas coordinates)
//
// Returns encoded blocks in the same order as input rectangles.
func (p *BlockEncoderPool) EncodeBlocks(img *image.RGBA, srcRects, outRects []image.Rectangle) []*[]byte {
	startTime := time.Now()
	n := len(srcRects)
	if n == 0 {
		return make([]*[]byte, 0)
	}

	// For small block counts, encode sequentially (avoid goroutine overhead)
	if n <= 2 {
		result := p.encodeSequential(img, srcRects, outRects)
		elapsed := time.Since(startTime)
		if elapsed > 50*time.Millisecond {
			log.Printf("[WARN] block_encoder_pool: slow sequential encode blocks=%d elapsed_ms=%d", n, elapsed.Milliseconds())
		}
		return result
	}

	// Create buffered result channel
	resultCh := make(chan blockResult, n)

	// Submit all jobs
	for i := 0; i < n; i++ {
		p.stats.jobsSubmitted.Add(1)

		job := blockJob{
			img:      img,
			srcRect:  srcRects[i],
			outRect:  outRects[i],
			seqNum:   i,
			resultCh: resultCh,
		}

		select {
		case p.jobs <- job:
		case <-p.ctx.Done():
			// Pool shutting down, return what we have
			return make([]*[]byte, 0)
		}
	}

	// Collect results (may arrive out of order)
	results := make([]blockResult, n)
	for i := 0; i < n; i++ {
		select {
		case r := <-resultCh:
			results[r.seqNum] = r
		case <-p.ctx.Done():
			return make([]*[]byte, 0)
		}
	}

	// Convert to output format (preserving order via seqNum)
	output := make([]*[]byte, n)
	for i := 0; i < n; i++ {
		data := results[i].data
		output[i] = &data
	}

	// Log performance metrics periodically (every 100 calls)
	completed := p.stats.jobsCompleted.Load()
	elapsed := time.Since(startTime)
	if completed%100 == 0 && completed > 0 {
		log.Printf("[INFO] block_encoder_pool: parallel encode blocks=%d elapsed_ms=%d workers=%d jobs_completed=%d effective_blocks_per_sec=%.1f",
			n, elapsed.Milliseconds(), p.workers, completed, float64(n)/elapsed.Seconds())
	}

	return output
}

// encodeSequential handles small block counts without parallelism overhead.
func (p *BlockEncoderPool) encodeSequential(img *image.RGBA, srcRects, outRects []image.Rectangle) []*[]byte {
	result := make([]*[]byte, len(srcRects))

	for i := range srcRects {
		blockData, codecType := getImageBlock(img, srcRects[i])
		blockData = makeImageBlock(blockData, outRects[i], codecType)
		result[i] = &blockData
	}

	return result
}

// Stats returns current pool statistics.
func (p *BlockEncoderPool) Stats() (submitted, completed uint64) {
	return p.stats.jobsSubmitted.Load(), p.stats.jobsCompleted.Load()
}

// WorkerCount returns the number of workers in the pool.
func (p *BlockEncoderPool) WorkerCount() int {
	return p.workers
}
