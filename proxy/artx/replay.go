package artx

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	replayCacheTTL      = 180 * time.Second
	replayCacheCapacity = 65536
)

var (
	errReplay          = errors.New("artx: replay detected")
	errReplayCacheFull = errors.New("artx: replay cache full")
)

type replayKey [UserLocatorLength + AuthTagLength + 4]byte

type replayCache struct {
	mu       sync.Mutex
	entries  map[replayKey]time.Time
	queue    []replayEntry
	head     int
	capacity int
	ttl      time.Duration
	now      func() time.Time
}

type replayEntry struct {
	key       replayKey
	expiresAt time.Time
}

func newReplayCache(capacity int, ttl time.Duration, now func() time.Time) *replayCache {
	return &replayCache{entries: make(map[replayKey]time.Time), capacity: capacity, ttl: ttl, now: now}
}

func (cache *replayCache) add(key replayKey) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.now()
	cache.evictExpired(now)
	if _, found := cache.entries[key]; found {
		return errReplay
	}
	if len(cache.entries) >= cache.capacity {
		return errReplayCacheFull
	}
	expiresAt := now.Add(cache.ttl)
	cache.entries[key] = expiresAt
	cache.queue = append(cache.queue, replayEntry{key: key, expiresAt: expiresAt})
	return nil
}

func (cache *replayCache) evictExpired(now time.Time) {
	for cache.head < len(cache.queue) && !cache.queue[cache.head].expiresAt.After(now) {
		entry := cache.queue[cache.head]
		delete(cache.entries, entry.key)
		cache.head++
	}
	if cache.head >= 1024 && cache.head*2 >= len(cache.queue) {
		cache.queue = append(cache.queue[:0], cache.queue[cache.head:]...)
		cache.head = 0
	}
}

func replayKeyFor(frame AuthFrame) replayKey {
	var key replayKey
	offset := copy(key[:], frame.UserLocator[:])
	offset += copy(key[offset:], frame.AuthTag[:])
	binary.BigEndian.PutUint32(key[offset:], frame.TimestampBucket)
	return key
}
