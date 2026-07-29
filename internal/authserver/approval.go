package authserver

import (
	"context"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultApprovalTTL is how long an approved value-ref stays approved before
	// the next request for it prompts again.
	DefaultApprovalTTL = 10 * time.Minute
	// minApprovalTTL and maxApprovalTTL clamp the configurable timeout.
	minApprovalTTL = 0
	maxApprovalTTL = 60 * time.Minute
)

// PromptRequest describes a single credential the server is about to resolve on
// behalf of a client command, so a Prompter can show the user what is being
// requested and by whom.
type PromptRequest struct {
	// Command is the client command (tool + args) that triggered the request.
	Command []string
	// CredentialName is the config credential entry the ref belongs to.
	CredentialName string
	// Ref is the value-ref being resolved (e.g. op://Vault/Item/field). It is a
	// reference, not the secret itself, so it is safe to display.
	Ref string
}

// Prompter asks the host user to approve resolving a single credential. Confirm
// returns true to allow resolution, false to deny. It must honor ctx (e.g. a
// per-request timeout) and should fail closed (return false) rather than block
// indefinitely.
type Prompter interface {
	Confirm(ctx context.Context, req PromptRequest) (bool, error)
}

// authOutcome reports the result of an approval check so the caller can tell a
// silent resolution (which warrants a desktop notification) apart from one the
// user was actively prompted for (the dialog is itself the notification) or a
// denial (nothing is resolved).
type authOutcome int

const (
	// outcomeDenied means resolution is not permitted: the user denied the
	// prompt, or there was no way to prompt.
	outcomeDenied authOutcome = iota
	// outcomePrompted means the user was shown an approval dialog and allowed
	// resolution.
	outcomePrompted
	// outcomeSilent means resolution is permitted without prompting the user: a
	// fresh cached approval, an auto-approve gate, or no gate at all.
	outcomeSilent
)

// allowed reports whether the outcome permits resolution.
func (o authOutcome) allowed() bool { return o != outcomeDenied }

// approvalCache gates credential resolution behind a host-side confirmation.
// Each distinct value-ref must be approved by the user; an approval is then
// cached for ttl so repeated requests for the same secret within the window
// resolve without re-prompting. Approvals live only in memory and are lost on
// restart.
type approvalCache struct {
	mu          sync.Mutex
	ttl         time.Duration
	prompter    Prompter
	autoApprove bool
	approved    map[string]time.Time
	// now is overridable in tests; defaults to time.Now.
	now func() time.Time
}

// newApprovalCache builds a cache with ttl clamped to [minApprovalTTL,
// maxApprovalTTL]. When autoApprove is true the gate is disabled and every
// request is allowed without prompting.
func newApprovalCache(ttl time.Duration, autoApprove bool, p Prompter) *approvalCache {
	switch {
	case ttl < minApprovalTTL:
		ttl = minApprovalTTL
	case ttl > maxApprovalTTL:
		ttl = maxApprovalTTL
	}
	return &approvalCache{
		ttl:         ttl,
		prompter:    p,
		autoApprove: autoApprove,
		approved:    map[string]time.Time{},
		now:         time.Now,
	}
}

// authorize reports whether resolving req.Ref is currently allowed, and whether
// the decision was reached silently or by prompting the user. A nil cache (gate
// not installed) or an auto-approve cache allows silently. A fresh cached
// approval allows silently; otherwise the user is prompted and, on approval, the
// ref is stamped so subsequent requests within ttl are silent.
//
// The cache mutex is held across the prompt so only one dialog is shown at a
// time and concurrent requests for the same ref coalesce: waiters re-check the
// cache after the lock frees and find the fresh approval.
func (a *approvalCache) authorize(ctx context.Context, req PromptRequest) (authOutcome, error) {
	if a == nil || a.autoApprove {
		return outcomeSilent, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if t, ok := a.approved[req.Ref]; ok && a.now().Before(t.Add(a.ttl)) {
		return outcomeSilent, nil
	}

	if a.prompter == nil {
		// A gate with no way to prompt fails closed rather than silently allowing.
		return outcomeDenied, nil
	}

	ok, err := a.prompter.Confirm(ctx, req)
	if err != nil {
		return outcomeDenied, err
	}
	if !ok {
		return outcomeDenied, nil
	}
	a.approved[req.Ref] = a.now()
	return outcomePrompted, nil
}

// promptText renders the human-facing body for a confirmation prompt.
func promptText(req PromptRequest) string {
	var b strings.Builder
	b.WriteString("Allow this command to use a credential?\n\n")
	b.WriteString(strings.Join(req.Command, " "))
	b.WriteString("\n\n")
	if req.CredentialName != "" {
		b.WriteString(req.CredentialName)
		b.WriteString("\n  ↳ ")
	}
	b.WriteString(req.Ref)
	return b.String()
}
