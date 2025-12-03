package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const authSessionsCollection = "auth_sessions"

// AuthSession represents a user authentication session stored in MongoDB
type AuthSession struct {
	Token     string    `bson:"_id"`
	Username  string    `bson:"username"`
	Role      string    `bson:"role"`
	CreatedAt time.Time `bson:"createdAt"`
	ExpiresAt time.Time `bson:"expiresAt"`
	LastSeen  time.Time `bson:"lastSeen"`
	IP        string    `bson:"ip,omitempty"`
	UserAgent string    `bson:"userAgent,omitempty"`
}

// AuthSessionRepository handles auth session persistence
type AuthSessionRepository struct {
	collection *mongo.Collection
}

// NewAuthSessionRepository creates a new auth session repository
func NewAuthSessionRepository() *AuthSessionRepository {
	if mongoDB == nil {
		return nil
	}
	return &AuthSessionRepository{
		collection: mongoDB.Collection(authSessionsCollection),
	}
}

// CreateSession stores a new auth session in MongoDB
func (r *AuthSessionRepository) CreateSession(ctx context.Context, session *AuthSession) error {
	if r == nil || r.collection == nil {
		return fmt.Errorf("auth session repository not initialized")
	}

	_, err := r.collection.InsertOne(ctx, session)
	if err != nil {
		return fmt.Errorf("failed to create auth session: %w", err)
	}
	return nil
}

// GetSession retrieves an auth session by token
func (r *AuthSessionRepository) GetSession(ctx context.Context, token string) (*AuthSession, error) {
	if r == nil || r.collection == nil {
		return nil, fmt.Errorf("auth session repository not initialized")
	}

	var session AuthSession
	err := r.collection.FindOne(ctx, bson.M{"_id": token}).Decode(&session)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get auth session: %w", err)
	}
	return &session, nil
}

// UpdateLastSeen updates the last seen timestamp for a session
func (r *AuthSessionRepository) UpdateLastSeen(ctx context.Context, token string) error {
	if r == nil || r.collection == nil {
		return fmt.Errorf("auth session repository not initialized")
	}

	_, err := r.collection.UpdateByID(ctx, token, bson.M{
		"$set": bson.M{
			"lastSeen": time.Now().UTC(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update auth session lastSeen: %w", err)
	}
	return nil
}

// DeleteSession removes an auth session by token
func (r *AuthSessionRepository) DeleteSession(ctx context.Context, token string) error {
	if r == nil || r.collection == nil {
		return fmt.Errorf("auth session repository not initialized")
	}

	_, err := r.collection.DeleteOne(ctx, bson.M{"_id": token})
	if err != nil {
		return fmt.Errorf("failed to delete auth session: %w", err)
	}
	return nil
}

// DeleteExpiredSessions removes all expired auth sessions
func (r *AuthSessionRepository) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	if r == nil || r.collection == nil {
		return 0, fmt.Errorf("auth session repository not initialized")
	}

	result, err := r.collection.DeleteMany(ctx, bson.M{
		"expiresAt": bson.M{"$lte": time.Now().UTC()},
	})
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired auth sessions: %w", err)
	}
	return result.DeletedCount, nil
}

// DeleteSessionsByUsername removes all sessions for a user (for logout all devices)
func (r *AuthSessionRepository) DeleteSessionsByUsername(ctx context.Context, username string) (int64, error) {
	if r == nil || r.collection == nil {
		return 0, fmt.Errorf("auth session repository not initialized")
	}

	result, err := r.collection.DeleteMany(ctx, bson.M{"username": username})
	if err != nil {
		return 0, fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return result.DeletedCount, nil
}

// LoadAllValidSessions loads all non-expired sessions (for server startup)
func (r *AuthSessionRepository) LoadAllValidSessions(ctx context.Context) ([]*AuthSession, error) {
	if r == nil || r.collection == nil {
		return nil, fmt.Errorf("auth session repository not initialized")
	}

	cursor, err := r.collection.Find(ctx, bson.M{
		"expiresAt": bson.M{"$gt": time.Now().UTC()},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load auth sessions: %w", err)
	}
	defer cursor.Close(ctx)

	var sessions []*AuthSession
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, fmt.Errorf("failed to decode auth sessions: %w", err)
	}
	return sessions, nil
}

// CountActiveSessions returns the count of active (non-expired) sessions
func (r *AuthSessionRepository) CountActiveSessions(ctx context.Context) (int64, error) {
	if r == nil || r.collection == nil {
		return 0, fmt.Errorf("auth session repository not initialized")
	}

	return r.collection.CountDocuments(ctx, bson.M{
		"expiresAt": bson.M{"$gt": time.Now().UTC()},
	})
}

// CreateAuthSessionIndexes creates indexes for the auth_sessions collection
func CreateAuthSessionIndexes(ctx context.Context) error {
	if mongoDB == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	col := mongoDB.Collection(authSessionsCollection)
	indexes := []mongo.IndexModel{
		// Username index for user session lookup
		{
			Keys:    bson.D{{Key: "username", Value: 1}},
			Options: options.Index().SetName("username_1"),
		},
		// ExpiresAt TTL index for automatic cleanup
		{
			Keys: bson.D{{Key: "expiresAt", Value: 1}},
			Options: options.Index().
				SetExpireAfterSeconds(0). // MongoDB will delete docs when expiresAt is reached
				SetName("expiresAt_ttl"),
		},
		// LastSeen index for activity tracking
		{
			Keys:    bson.D{{Key: "lastSeen", Value: 1}},
			Options: options.Index().SetName("lastSeen_1"),
		},
	}

	_, err := col.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create auth_sessions indexes: %w", err)
	}
	return nil
}
