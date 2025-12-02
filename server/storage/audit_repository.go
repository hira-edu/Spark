package storage

import (
	"context"
	"fmt"
	"time"
)

const auditsCollection = "audits"

type Audit struct {
	Timestamp time.Time         `bson:"ts"`
	Actor     string            `bson:"actor,omitempty"`
	Action    string            `bson:"action"`
	Target    map[string]string `bson:"target,omitempty"`
	Outcome   string            `bson:"outcome,omitempty"`
	Meta      map[string]any    `bson:"meta,omitempty"`
}

// WriteAudit inserts an audit event.
func WriteAudit(ctx context.Context, audit Audit) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	if audit.Timestamp.IsZero() {
		audit.Timestamp = time.Now().UTC()
	}
	_, err := db.Collection(auditsCollection).InsertOne(ctx, audit)
	return err
}
