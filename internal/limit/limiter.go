package limit

import (
	"sync"
	"time"
)

type (
	register struct {
		start    time.Time
		duration time.Duration
	}

	Limiter struct {
		*sync.Mutex
		limits map[string]register
	}
)

func (limiter *Limiter) LimitAndCheck(key string, duration time.Duration) bool {
	now := time.Now()
	limiter.Lock()
	r, found := limiter.limits[key]
	limiter.Unlock()
	limiter.Lock()
	limiter.limits[key] = register{
		start:    now,
		duration: duration,
	}
	limiter.Unlock()
	if found {
		return time.Now().After(r.start.Add(r.duration))
	}
	return true
}

func NewLimiter() *Limiter {
	result := &Limiter{
		Mutex:  new(sync.Mutex),
		limits: map[string]register{},
	}
	go func(limiter *Limiter) {
		for {
			time.Sleep(10 * time.Minute)
			limiter.Lock()
			for key, r := range limiter.limits {
				if time.Now().After(r.start.Add(r.duration)) {
					delete(limiter.limits, key)
				}
			}
			limiter.Unlock()
		}
	}(result)
	return result
}
