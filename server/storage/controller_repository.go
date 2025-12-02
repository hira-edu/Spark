package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const controllersCollection = "controllers"

// Controller represents a controller/server node in the cluster.
type Controller struct {
	ID           string    `bson:"_id"`
	LastSeen     time.Time `bson:"lastSeen"`
	Meta         any       `bson:"meta,omitempty"`
	CapacityHint int       `bson:"capacityHint,omitempty"`
	Status       string    `bson:"status,omitempty"`
	CreatedAt    time.Time `bson:"createdAt"`
	UpdatedAt    time.Time `bson:"updatedAt"`
}

// UpsertController registers or refreshes a controller record.
func UpsertController(ctx context.Context, id string, meta any, capacityHint int) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"lastSeen":     now,
			"meta":         meta,
			"capacityHint": capacityHint,
			"status":       "online",
			"updatedAt":    now,
		},
		"$setOnInsert": bson.M{
			"createdAt": now,
		},
	}
	_, err := db.Collection(controllersCollection).UpdateByID(ctx, id, update, options.Update().SetUpsert(true))
	return err
}

// TouchController updates the lastSeen timestamp for an existing controller.
func TouchController(ctx context.Context, id string) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	_, err := db.Collection(controllersCollection).UpdateByID(ctx, id, bson.M{
		"$set": bson.M{
			"lastSeen":  time.Now().UTC(),
			"status":    "online",
			"updatedAt": time.Now().UTC(),
		},
	}, options.Update().SetUpsert(true))
	return err
}

// MarkControllerStatus updates the controller status field (e.g., online/stale/offline).
func MarkControllerStatus(ctx context.Context, id, status string) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	_, err := db.Collection(controllersCollection).UpdateByID(ctx, id, bson.M{
		"$set": bson.M{
			"status":    status,
			"updatedAt": time.Now().UTC(),
		},
	}, options.Update().SetUpsert(true))
	return err
}

// GetController fetches a controller by ID.
func GetController(ctx context.Context, id string) (*Controller, error) {
	db := GetMongoDB()
	if db == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}
	var ctrl Controller
	if err := db.Collection(controllersCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&ctrl); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &ctrl, nil
}

// CountControllers returns the count of controllers matching the filter.
// If filter is nil, it counts all controllers.
func CountControllers(ctx context.Context, filter any) (int64, error) {
	db := GetMongoDB()
	if db == nil {
		return 0, fmt.Errorf("MongoDB not initialized")
	}
	if filter == nil {
		filter = bson.M{}
	}
	return db.Collection(controllersCollection).CountDocuments(ctx, filter)
}
