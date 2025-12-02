package storage

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

// ReleaseExpiredDevices clears controller ownership for devices whose leases have expired.
func ReleaseExpiredDevices(ctx context.Context, now time.Time) error {
	db := GetMongoDB()
	if db == nil {
		return nil
	}
	_, err := db.Collection(devicesCollection).UpdateMany(ctx, bson.M{
		"leaseExpiresAt": bson.M{"$lte": now},
	}, bson.M{
		"$set": bson.M{
			"controllerId":   "",
			"status":         "offline",
			"updatedAt":      now,
			"leaseExpiresAt": time.Time{},
		},
	})
	return err
}

// ExpireSessions marks sessions whose leases have expired as closed.
func ExpireSessions(ctx context.Context, now time.Time) error {
	db := GetMongoDB()
	if db == nil {
		return nil
	}
	_, err := db.Collection(sessionsCollection).UpdateMany(ctx, bson.M{
		"leaseExpiresAt": bson.M{"$lte": now},
		"state":         bson.M{"$ne": "closed"},
	}, bson.M{
		"$set": bson.M{
			"state":     "closed",
			"updatedAt": now,
		},
	})
	return err
}

// MarkStaleControllers marks controllers as stale if they haven't heartbeat recently.
func MarkStaleControllers(ctx context.Context, cutoff time.Time) error {
	db := GetMongoDB()
	if db == nil {
		return nil
	}
	_, err := db.Collection(controllersCollection).UpdateMany(ctx, bson.M{
		"lastSeen": bson.M{"$lt": cutoff},
	}, bson.M{
		"$set": bson.M{
			"status":    "stale",
			"updatedAt": time.Now().UTC(),
		},
	})
	return err
}
