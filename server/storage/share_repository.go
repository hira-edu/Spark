package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ShareEntry represents a desktop sharing session
type ShareEntry struct {
	ID           string           `bson:"_id" json:"id"`
	Device       string           `bson:"device" json:"device"`
	Desktop      string           `bson:"desktop" json:"desktop"`
	Token        string           `bson:"token" json:"token"`
	Secret       string           `bson:"secret" json:"secret"` // hex-encoded server-generated secret for guest WS
	ExpiresAt    time.Time        `bson:"expiresAt" json:"expiresAt"`
	SingleUse    bool             `bson:"singleUse" json:"singleUse"`
	ViewOnly     bool             `bson:"viewOnly" json:"viewOnly"`
	TurnOnly     bool             `bson:"turnOnly" json:"turnOnly"`
	Used         bool             `bson:"used" json:"used"`
	UsedAt       time.Time        `bson:"usedAt,omitempty" json:"usedAt,omitempty"`
	UsedBy       string           `bson:"usedBy,omitempty" json:"usedBy,omitempty"`
	CreatedAt    time.Time        `bson:"createdAt" json:"createdAt"`
	CreatedBy    string           `bson:"createdBy" json:"createdBy"` // Admin who created
	RevokedAt    time.Time        `bson:"revokedAt,omitempty" json:"revokedAt,omitempty"`
	RevokedBy    string           `bson:"revokedBy,omitempty" json:"revokedBy,omitempty"`
	RevokeReason string           `bson:"revokeReason,omitempty" json:"revokeReason,omitempty"`
	AccessLog    []AccessLogEntry `bson:"accessLog,omitempty" json:"accessLog,omitempty"`
}

// AccessLogEntry records guest access attempts
type AccessLogEntry struct {
	Timestamp time.Time `bson:"timestamp" json:"timestamp"`
	IP        string    `bson:"ip" json:"ip"`
	UserAgent string    `bson:"userAgent" json:"userAgent"` // Truncated to 200 chars
	Success   bool      `bson:"success" json:"success"`
	Reason    string    `bson:"reason,omitempty" json:"reason,omitempty"`
}

// ShareRepository handles share persistence
type ShareRepository struct {
	col *mongo.Collection
}

// NewShareRepository creates a new share repository
func NewShareRepository() *ShareRepository {
	return &ShareRepository{
		col: GetCollection("shares"),
	}
}

// ensureCollection binds the collection lazily after Mongo initializes.
func (r *ShareRepository) ensureCollection() *mongo.Collection {
	if r.col != nil {
		return r.col
	}
	r.col = GetCollection("shares")
	return r.col
}

// Create inserts a new share
func (r *ShareRepository) Create(ctx context.Context, share *ShareEntry) error {
	if r.ensureCollection() == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	_, err := r.col.InsertOne(ctx, share)
	if err != nil {
		return fmt.Errorf("failed to create share: %w", err)
	}

	return nil
}

// GetByID retrieves a share by ID
func (r *ShareRepository) GetByID(ctx context.Context, id string) (*ShareEntry, error) {
	if r.ensureCollection() == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	var share ShareEntry
	err := r.col.FindOne(ctx, bson.M{"_id": id}).Decode(&share)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get share: %w", err)
	}

	return &share, nil
}

// GetByToken retrieves a share by token
func (r *ShareRepository) GetByToken(ctx context.Context, token string) (*ShareEntry, error) {
	if r.ensureCollection() == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	var share ShareEntry
	err := r.col.FindOne(ctx, bson.M{"token": token}).Decode(&share)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get share by token: %w", err)
	}

	return &share, nil
}

// MarkUsed atomically marks a single-use token as used
// Returns error if already used (prevents race condition)
func (r *ShareRepository) MarkUsed(ctx context.Context, id, usedBy string) error {
	if r.ensureCollection() == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	// Atomic update: only mark as used if not already used
	filter := bson.M{
		"_id":  id,
		"used": false, // Only update if not used
	}

	update := bson.M{
		"$set": bson.M{
			"used":   true,
			"usedAt": time.Now(),
			"usedBy": usedBy,
		},
	}

	result, err := r.col.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to mark share as used: %w", err)
	}

	// If no documents were updated, token was already used
	if result.MatchedCount == 0 {
		return fmt.Errorf("token already used or not found")
	}

	return nil
}

// UpdateDesktop updates the desktop UUID for a share
func (r *ShareRepository) UpdateDesktop(ctx context.Context, id, desktop string) error {
	if r.ensureCollection() == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	filter := bson.M{"_id": id}
	update := bson.M{
		"$set": bson.M{
			"desktop": desktop,
		},
	}

	_, err := r.col.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update desktop: %w", err)
	}

	return nil
}

// AppendAccessLog appends an access log entry (limited to last 100 entries)
func (r *ShareRepository) AppendAccessLog(ctx context.Context, token string, entry AccessLogEntry) error {
	if r.ensureCollection() == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	// Truncate User-Agent to 200 chars to prevent abuse
	if len(entry.UserAgent) > 200 {
		entry.UserAgent = entry.UserAgent[:200]
	}

	filter := bson.M{"token": token}
	update := bson.M{
		"$push": bson.M{
			"accessLog": bson.M{
				"$each":  []AccessLogEntry{entry},
				"$slice": -100, // Keep only last 100 entries
			},
		},
	}

	_, err := r.col.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to append access log: %w", err)
	}

	return nil
}

// ListAll returns all shares (with pagination)
func (r *ShareRepository) ListAll(ctx context.Context, limit, skip int) ([]*ShareEntry, error) {
	if r.col == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(skip)).
		SetSort(bson.D{{Key: "createdAt", Value: -1}})

	cursor, err := r.col.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares: %w", err)
	}
	defer cursor.Close(ctx)

	var shares []*ShareEntry
	if err := cursor.All(ctx, &shares); err != nil {
		return nil, fmt.Errorf("failed to decode shares: %w", err)
	}

	return shares, nil
}

// ListByDevice returns all shares for a device
func (r *ShareRepository) ListByDevice(ctx context.Context, deviceID string) ([]*ShareEntry, error) {
	if r.col == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	cursor, err := r.col.Find(ctx, bson.M{"device": deviceID})
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by device: %w", err)
	}
	defer cursor.Close(ctx)

	var shares []*ShareEntry
	if err := cursor.All(ctx, &shares); err != nil {
		return nil, fmt.Errorf("failed to decode shares: %w", err)
	}

	return shares, nil
}

// Delete removes a share by ID
func (r *ShareRepository) Delete(ctx context.Context, id string) error {
	if r.ensureCollection() == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	_, err := r.col.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete share: %w", err)
	}

	return nil
}

// DeleteByDevice removes all shares for a device
func (r *ShareRepository) DeleteByDevice(ctx context.Context, deviceID string) (int64, error) {
	if r.ensureCollection() == nil {
		return 0, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	result, err := r.col.DeleteMany(ctx, bson.M{"device": deviceID})
	if err != nil {
		return 0, fmt.Errorf("failed to delete shares by device: %w", err)
	}

	return result.DeletedCount, nil
}

// DeleteExpired removes all expired shares
func (r *ShareRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	if r.ensureCollection() == nil {
		return 0, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	// Delete shares where expiresAt is not zero and before the given time
	filter := bson.M{
		"expiresAt": bson.M{
			"$gt": time.Time{}, // Not zero
			"$lt": before,      // Before given time
		},
	}

	result, err := r.col.DeleteMany(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired shares: %w", err)
	}

	return result.DeletedCount, nil
}

// CountByDevice counts shares for a device
func (r *ShareRepository) CountByDevice(ctx context.Context, deviceID string) (int64, error) {
	if r.ensureCollection() == nil {
		return 0, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	count, err := r.col.CountDocuments(ctx, bson.M{"device": deviceID})
	if err != nil {
		return 0, fmt.Errorf("failed to count shares: %w", err)
	}

	return count, nil
}

// CountByCreator counts shares created by an admin
func (r *ShareRepository) CountByCreator(ctx context.Context, creatorID string) (int64, error) {
	if r.col == nil {
		return 0, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	count, err := r.col.CountDocuments(ctx, bson.M{"createdBy": creatorID})
	if err != nil {
		return 0, fmt.Errorf("failed to count shares by creator: %w", err)
	}

	return count, nil
}
