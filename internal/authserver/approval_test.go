package authserver

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakePrompter struct {
	mu    sync.Mutex
	calls int
	allow bool
	err   error
}

func (f *fakePrompter) Confirm(_ context.Context, _ PromptRequest) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.allow, f.err
}

func (f *fakePrompter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestApprovalCache_TTLClamped(t *testing.T) {
	require.Equal(t, time.Duration(minApprovalTTL), newApprovalCache(-time.Second, false, nil).ttl) // below min → clamped up
	require.Equal(t, maxApprovalTTL, newApprovalCache(2*time.Hour, false, nil).ttl)                 // above max → clamped down
	require.Equal(t, 3*time.Minute, newApprovalCache(3*time.Minute, false, nil).ttl)                // within range → unchanged
}

func TestApprovalCache_NilAndAutoApprove(t *testing.T) {
	ctx := context.Background()

	// nil cache permits silently
	var nilCache *approvalCache
	o, err := nilCache.authorize(ctx, PromptRequest{Ref: "op://v/i/f"})
	require.NoError(t, err)
	require.Equal(t, outcomeSilent, o)

	// auto-approve permits silently without a prompter
	c := newApprovalCache(DefaultApprovalTTL, true, nil)
	o, err = c.authorize(ctx, PromptRequest{Ref: "op://v/i/f"})
	require.NoError(t, err)
	require.Equal(t, outcomeSilent, o)
}

func TestApprovalCache_NoPrompterFailsClosed(t *testing.T) {
	c := newApprovalCache(DefaultApprovalTTL, false, nil)
	o, err := c.authorize(context.Background(), PromptRequest{Ref: "op://v/i/f"})
	require.NoError(t, err)
	require.Equal(t, outcomeDenied, o)
}

func TestApprovalCache_ApproveThenCached(t *testing.T) {
	p := &fakePrompter{allow: true}
	c := newApprovalCache(DefaultApprovalTTL, false, p)

	for i := 0; i < 3; i++ {
		o, err := c.authorize(context.Background(), PromptRequest{Ref: "op://v/i/f"})
		require.NoError(t, err)
		// first call prompts the user; the next two are served silently from cache
		if i == 0 {
			require.Equal(t, outcomePrompted, o)
		} else {
			require.Equal(t, outcomeSilent, o)
		}
	}
	// prompted once; the next two were served from cache
	require.Equal(t, 1, p.count())

	// a different ref prompts separately
	o, err := c.authorize(context.Background(), PromptRequest{Ref: "op://v/other/f"})
	require.NoError(t, err)
	require.Equal(t, outcomePrompted, o)
	require.Equal(t, 2, p.count())
}

func TestApprovalCache_DenyNotCached(t *testing.T) {
	p := &fakePrompter{allow: false}
	c := newApprovalCache(DefaultApprovalTTL, false, p)

	for i := 0; i < 2; i++ {
		o, err := c.authorize(context.Background(), PromptRequest{Ref: "op://v/i/f"})
		require.NoError(t, err)
		require.Equal(t, outcomeDenied, o)
	}
	// a denial is never cached, so each request re-prompts
	require.Equal(t, 2, p.count())
}

func TestApprovalCache_Expiry(t *testing.T) {
	p := &fakePrompter{allow: true}
	c := newApprovalCache(2*time.Minute, false, p)

	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }

	o, err := c.authorize(context.Background(), PromptRequest{Ref: "op://v/i/f"})
	require.NoError(t, err)
	require.Equal(t, outcomePrompted, o)
	require.Equal(t, 1, p.count())

	// within TTL: cached (silent)
	now = now.Add(90 * time.Second)
	o, _ = c.authorize(context.Background(), PromptRequest{Ref: "op://v/i/f"})
	require.Equal(t, outcomeSilent, o)
	require.Equal(t, 1, p.count())

	// past TTL: re-prompts
	now = now.Add(2 * time.Minute)
	o, _ = c.authorize(context.Background(), PromptRequest{Ref: "op://v/i/f"})
	require.Equal(t, outcomePrompted, o)
	require.Equal(t, 2, p.count())
}

func TestApprovalCache_ConcurrentSameRefCoalesces(t *testing.T) {
	p := &fakePrompter{allow: true}
	c := newApprovalCache(DefaultApprovalTTL, false, p)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, err := c.authorize(context.Background(), PromptRequest{Ref: "op://v/i/f"})
			require.NoError(t, err)
			require.True(t, o.allowed())
		}()
	}
	wg.Wait()

	// serialized under the cache lock: the first prompt stamps the approval and
	// the rest are served from cache, so the user is asked exactly once.
	require.Equal(t, 1, p.count())
}
