package session_cache

import (
	"container/heap"
	"log"
	"sync"
	"time"
)

type CacheInfo struct {
	TargetSessionId string
	ExpiresAt       time.Time
}

type Entry struct {
	Key       string
	Info      CacheInfo
	heapIndex int
}

type ExpirationHeap []*Entry

func (h ExpirationHeap) Len() int { return len(h) }

func (h ExpirationHeap) Less(i, j int) bool {
	return h[i].Info.ExpiresAt.Before(h[j].Info.ExpiresAt)
}

func (h ExpirationHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}

func (h *ExpirationHeap) Push(x interface{}) {
	n := len(*h)
	entry := x.(*Entry)
	entry.heapIndex = n
	*h = append(*h, entry)
}

func (h *ExpirationHeap) Pop() interface{} {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	entry.heapIndex = -1
	*h = old[0 : n-1]
	return entry
}

type HeapCache struct {
	capacity int
	cache    map[string]*Entry
	expHeap  *ExpirationHeap
	mu       sync.RWMutex
}

var CacheInstance *HeapCache

func NewHeapCache(capacity int) *HeapCache {
	h := &ExpirationHeap{}
	heap.Init(h)
	return &HeapCache{
		capacity: capacity,
		cache:    make(map[string]*Entry),
		expHeap:  h,
	}
}

func (c *HeapCache) Set(key string, targetSessionId string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	if existingEntry, exists := c.cache[key]; exists {
		heap.Remove(c.expHeap, existingEntry.heapIndex)
		delete(c.cache, key)
	}

	if len(c.cache) >= c.capacity {
		c.evictEarliest()
	}

	entry := &Entry{
		Key: key,
		Info: CacheInfo{
			TargetSessionId: targetSessionId,
			ExpiresAt:       time.Now().Add(ttl),
		},
	}

	c.cache[key] = entry
	heap.Push(c.expHeap, entry)
}

func (c *HeapCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return "", false
	}

	if time.Now().After(entry.Info.ExpiresAt) {
		return "", false
	}

	return entry.Info.TargetSessionId, true
}

func (c *HeapCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.cache[key]; exists {
		heap.Remove(c.expHeap, entry.heapIndex)
		delete(c.cache, key)
	}
}

func (c *HeapCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

func (c *HeapCache) evictEarliest() {
	if c.expHeap.Len() > 0 {

		if time.Now().After((*c.expHeap)[0].Info.ExpiresAt) {

		} else {

			secondsLeft := int((*c.expHeap)[0].Info.ExpiresAt.Sub(time.Now()).Seconds())
			log.Printf("Evicting session cache entry: %s, expires at %v, %d seconds left", (*c.expHeap)[0].Key, (*c.expHeap)[0].Info.ExpiresAt, secondsLeft)
		}
		entry := heap.Pop(c.expHeap).(*Entry)
		delete(c.cache, entry.Key)
	}
}

func (c *HeapCache) CleanExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for c.expHeap.Len() > 0 {
		entry := (*c.expHeap)[0]
		if now.After(entry.Info.ExpiresAt) {
			heap.Pop(c.expHeap)
			delete(c.cache, entry.Key)
			removed++
		} else {
			break
		}
	}

	return removed
}
