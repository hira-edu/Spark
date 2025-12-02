package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const devicesCollection = "devices"

type Device struct {
	ID             string                 `bson:"_id"`
	ControllerID   string                 `bson:"controllerId,omitempty"`
	Status         string                 `bson:"status,omitempty"`
	LastSeen       time.Time              `bson:"lastSeen"`
	LeaseExpiresAt time.Time              `bson:"leaseExpiresAt,omitempty"`
	Secret         string                 `bson:"secret,omitempty"`
	Meta           map[string]any         `bson:"meta,omitempty"`
	CreatedAt      time.Time              `bson:"createdAt"`
	UpdatedAt      time.Time              `bson:"updatedAt"`
	Tags           map[string]interface{} `bson:"tags,omitempty"`
}

// UpsertDevice registers or refreshes a device record and optionally sets a controller lease.
func UpsertDevice(ctx context.Context, id, controllerID string, lease time.Duration, meta map[string]any, secret string) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	now := time.Now().UTC()
	setFields := bson.M{
		"controllerId": controllerID,
		"status":       "online",
		"lastSeen":     now,
		"updatedAt":    now,
	}
	if meta != nil {
		setFields["meta"] = meta
	}
	if secret != "" {
		setFields["secret"] = secret
	}
	update := bson.M{
		"$set": setFields,
		"$setOnInsert": bson.M{
			"createdAt": now,
		},
	}
	if lease > 0 {
		update["$set"].(bson.M)["leaseExpiresAt"] = now.Add(lease)
	}
	_, err := db.Collection(devicesCollection).UpdateByID(ctx, id, update, options.Update().SetUpsert(true))
	return err
}

// ClaimDevice attempts to claim a device for the given controller when the lease is expired or unowned.
// Returns the resulting device document and whether the claim succeeded.
func ClaimDevice(ctx context.Context, id, controllerID string, lease time.Duration, meta map[string]any, secret string, allowExpired bool, staleControllers []string) (*Device, bool, error) {
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

	setFields := bson.M{
		"controllerId":   controllerID,
		"status":         "online",
		"lastSeen":       now,
		"leaseExpiresAt": now.Add(lease),
		"updatedAt":      now,
	}
	if meta != nil {
		setFields["meta"] = meta
	}
	if secret != "" {
		setFields["secret"] = secret
	}
	update := bson.M{
		"$set": setFields,
		"$setOnInsert": bson.M{
			"createdAt": now,
		},
	}

	var device Device
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After).SetUpsert(true)
	err := db.Collection(devicesCollection).FindOneAndUpdate(ctx, filter, update, opts).Decode(&device)
	if err == mongo.ErrNoDocuments {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &device, device.ControllerID == controllerID, nil
}

// GetDevice returns the device document by ID.
func GetDevice(ctx context.Context, id string) (*Device, error) {
	db := GetMongoDB()
	if db == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}
	var device Device
	if err := db.Collection(devicesCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&device); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}

// ReleaseDevice clears controller ownership and lease information.
func ReleaseDevice(ctx context.Context, id string) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	_, err := db.Collection(devicesCollection).UpdateByID(ctx, id, bson.M{
		"$set": bson.M{
			"controllerId":   "",
			"status":         "offline",
			"leaseExpiresAt": time.Time{},
			"updatedAt":      time.Now().UTC(),
		},
	}, options.Update().SetUpsert(true))
	return err
}

// MarkDeviceOffline marks a device as offline.
func MarkDeviceOffline(ctx context.Context, id string) error {
	db := GetMongoDB()
	if db == nil {
		return fmt.Errorf("MongoDB not initialized")
	}
	_, err := db.Collection(devicesCollection).UpdateByID(ctx, id, bson.M{
		"$set": bson.M{
			"status":         "offline",
			"controllerId":   "",
			"leaseExpiresAt": time.Time{},
			"updatedAt":      time.Now().UTC(),
		},
	}, options.Update().SetUpsert(true))
	return err
}

// CountDevices returns the number of device documents matching the filter.
// If filter is nil, it counts all devices.
func CountDevices(ctx context.Context, filter any) (int64, error) {
	db := GetMongoDB()
	if db == nil {
		return 0, fmt.Errorf("MongoDB not initialized")
	}
	if filter == nil {
		filter = bson.M{}
	}
	return db.Collection(devicesCollection).CountDocuments(ctx, filter)
}
