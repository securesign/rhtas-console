package services

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// TargetAuditEvent represents a target lifecycle event
type TargetAuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"` // "added", "revoked", "status_changed"
	RepoURL    string    `json:"repo_url"`
	TargetName string    `json:"target_name"`
	TargetType string    `json:"target_type"`
	OldStatus  string    `json:"old_status,omitempty"`
	NewStatus  string    `json:"new_status,omitempty"`
}

// TargetAuditLog provides thread-safe logging of target lifecycle events
type TargetAuditLog struct {
	filePath string
	mu       sync.Mutex
}

// NewTargetAuditLog creates a new audit log writing to the specified file
func NewTargetAuditLog(filePath string) *TargetAuditLog {
	return &TargetAuditLog{
		filePath: filePath,
	}
}

// LogEvent appends an audit event to the log file
func (a *TargetAuditLog) LogEvent(event TargetAuditEvent) error {
	if a == nil || a.filePath == "" {
		return nil // Audit logging disabled
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.OpenFile(a.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("failed to close audit log file: %v", cerr)
		}
	}()

	return json.NewEncoder(f).Encode(event)
}

// GetRevokedTargets reads the audit log and returns all revoked targets since the given time
func (a *TargetAuditLog) GetRevokedTargets(repoURL string, since time.Time) ([]TargetAuditEvent, error) {
	if a == nil || a.filePath == "" {
		return nil, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.Open(a.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No revocations yet
		}
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("failed to close audit log file: %v", cerr)
		}
	}()

	var revoked []TargetAuditEvent
	decoder := json.NewDecoder(f)

	for decoder.More() {
		var event TargetAuditEvent
		if err := decoder.Decode(&event); err != nil {
			continue // Skip malformed entries
		}

		if event.EventType == "revoked" &&
			event.RepoURL == repoURL &&
			event.Timestamp.After(since) {
			revoked = append(revoked, event)
		}
	}

	return revoked, nil
}
