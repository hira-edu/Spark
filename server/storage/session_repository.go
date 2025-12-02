package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const sessionsCollection = "sessions"

type Session struct {
	ID           string    `bson:"_id"`
	DeviceID     string    `bson:"deviceId"`
	UserID       string    `bson:"userId,omitempty"`
	Type         string    `bson:"type"`
	State        string    `bson:"state"`
	ControllerID string    `bson:"controllerId,omitempty"`
	LeaseExpires time.Time `bson:"leaseExpiresAt,omitempty"`
	CreatedAt    time.Time `bson:"createdAt"`
	UpdatedAt    time.Time `bson:"updatedAt"`
}

// StartSession creates or updates a session record with a lease.
func StartSession(ctx context.Context, id, deviceID, userID, sessionType, controllerID string, lease time.Duration) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"deviceId":       deviceID,
			"userId":         userID,
			"type":           sessionType,
			"state":          "active",
			"controllerId":   controllerID,
			"leaseExpiresAt": now.Add(lease),
			"updatedAt":      now,
		},
		"$setOnInsert": bson.M{
			"createdAt": now,
		},
	}
	_, err := db.Collection(sessionsCollection).UpdateByID(ctx, id, update, options.Update().SetUpsert(true))
	return err
}

// HeartbeatSession extends the lease for a session.
func HeartbeatSession(ctx context.Context, id string, lease time.Duration) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	now := time.Now().UTC()
	_, err := db.Collection(sessionsCollection).UpdateByID(ctx, id, bson.M{
		"$set": bson.M{
			"leaseExpiresAt": now.Add(lease),
			"updatedAt":      now,
		},
	})
	return err
}

// CloseSession marks a session as closed.
func CloseSession(ctx context.Context, id string) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	now := time.Now().UTC()
	_, err := db.Collection(sessionsCollection).UpdateByID(ctx, id, bson.M{
		"$set": bson.M{
			"state":     "closed",
			"updatedAt": now,
		},
	})
	return err
}

// GetSession returns a session by ID.
func GetSession(ctx context.Context, id string) (*Session, error) {
	db := GetMongoDB()
	if db == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}
	var session Session
	if err := db.Collection(sessionsCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&session); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &session, nil
}

// ClaimSession attempts to claim a stale or unowned session for the given controller.
func ClaimSession(ctx context.Context, id, controllerID string, lease time.Duration, sessionType, deviceID, userID string, allowExpired bool, staleControllers []string) (*Session, bool, error) {
	db := GetMongoDB()
	if db == nil {
		return nil, false, fmt.Errorf("MongoDB not initialized")
	}
	now := time.Now().UTC()
	filter := bson.M{
		"_id": id,
		"$or": []bson.M{
			{"controllerId": controllerID},
			{"controllerId": bson.M{"$exists": false}},
			{"controllerId": ""},
		},
	}
	if allowExpired {
		filter["$or"] = append(filter["$or"].([]bson.M), bson.M{
			"leaseExpiresAt": bson.M{"$lte": now},
		})
	}
	if len(staleControllers) > 0 {
		filter["$or"] = append(filter["$or"].([]bson.M), bson.M{
			"controllerId": bson.M{"$in": staleControllers},
		})
	}

	update := bson.M{
		"$set": bson.M{
			"deviceId":       deviceID,
			"userId":         userID,
			"type":           sessionType,
			"state":          "active",
			"controllerId":   controllerID,
			"leaseExpiresAt": now.Add(lease),
			"updatedAt":      now,
		},
		"$setOnInsert": bson.M{
			"createdAt": now,
		},
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After).SetUpsert(true)
	var session Session
	err := db.Collection(sessionsCollection).FindOneAndUpdate(ctx, filter, update, opts).Decode(&session)
	if err == mongo.ErrNoDocuments {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &session, session.ControllerID == controllerID, nil
}

// CountSessions returns the count of sessions matching the filter.
// If filter is nil, it counts all sessions.
func CountSessions(ctx context.Context, filter any) (int64, error) {
	db := GetMongoDB()
	if db == nil {
		return 0, fmt.Errorf("MongoDB not initialized")
	}
	if filter == nil {
		filter = bson.M{}
	}
	return db.Collection(sessionsCollection).CountDocuments(ctx, filter)
}
