package storage

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ClientLog represents a log entry from a client device
type ClientLog struct {
	ID         string    `bson:"_id,omitempty" json:"id"`
	DeviceID   string    `bson:"deviceId" json:"deviceId"`
	DeviceUUID string    `bson:"deviceUuid" json:"deviceUuid"`
	DeviceName string    `bson:"deviceName" json:"deviceName"`
	SessionID  uint32    `bson:"sessionId" json:"sessionId"`   // 0 = Session 0 (service), 1+ = user session
	Level      string    `bson:"level" json:"level"`           // INFO, WARN, ERROR, DEBUG
	Message    string    `bson:"message" json:"message"`       // Log message
	Data       bson.M    `bson:"data,omitempty" json:"data"`   // Structured data (JSON)
	Timestamp  time.Time `bson:"timestamp" json:"timestamp"`   // Client timestamp
	ReceivedAt time.Time `bson:"receivedAt" json:"receivedAt"` // Server timestamp
	Source     string    `bson:"source" json:"source"`         // File/function source
	Network    string    `bson:"network,omitempty" json:"network,omitempty"`
	Attempt    int       `bson:"attempt,omitempty" json:"attempt,omitempty"`
	CloseCode  int       `bson:"closeCode,omitempty" json:"closeCode,omitempty"`
	CloseReason string   `bson:"closeReason,omitempty" json:"closeReason,omitempty"`
}

// SaveClientLogs saves multiple client log entries to MongoDB
func SaveClientLogs(ctx context.Context, logs []ClientLog) error {
	db := GetMongoDB()
	if db == nil {
		return nil // Silently skip if MongoDB not enabled
	}

	if len(logs) == 0 {
		return nil
	}

	// Add server receive timestamp
	now := time.Now().UTC()
	docs := make([]interface{}, len(logs))
	for i := range logs {
		logs[i].ReceivedAt = now
		docs[i] = logs[i]
	}

	collection := db.Collection("client_logs")
	_, err := collection.InsertMany(ctx, docs)
	return err
}

// GetClientLogs retrieves client logs with filtering and pagination
func GetClientLogs(ctx context.Context, filter ClientLogFilter, limit int) ([]ClientLog, error) {
	db := GetMongoDB()
	if db == nil {
		return []ClientLog{}, nil // Return empty if MongoDB not enabled
	}

	collection := db.Collection("client_logs")

	// Build query filter
	query := bson.M{}
	if filter.DeviceID != "" {
		query["deviceId"] = filter.DeviceID
	}
	if filter.DeviceUUID != "" {
		query["deviceUuid"] = filter.DeviceUUID
	}
	if filter.SessionID != nil {
		query["sessionId"] = *filter.SessionID
	}
	if filter.Level != "" {
		query["level"] = filter.Level
	}
	if filter.MinLevel != "" {
		// Level priority: DEBUG < INFO < WARN < ERROR
		levelPriority := map[string]int{"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
		minPriority := levelPriority[filter.MinLevel]
		query["level"] = bson.M{"$in": getLevelsAtOrAbove(minPriority)}
	}
	if !filter.After.IsZero() {
		query["timestamp"] = bson.M{"$gte": filter.After}
	}
	if !filter.Before.IsZero() {
		if existing, ok := query["timestamp"].(bson.M); ok {
			existing["$lte"] = filter.Before
		} else {
			query["timestamp"] = bson.M{"$lte": filter.Before}
		}
	}

	// Query options
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}). // Newest first
		SetLimit(int64(limit))

	cursor, err := collection.Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []ClientLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}

	return logs, nil
}

// DeleteOldClientLogs removes logs older than the specified duration
func DeleteOldClientLogs(ctx context.Context, olderThan time.Duration) (int64, error) {
	db := GetMongoDB()
	if db == nil {
		return 0, nil // Skip if MongoDB not enabled
	}

	collection := db.Collection("client_logs")
	cutoff := time.Now().UTC().Add(-olderThan)

	result, err := collection.DeleteMany(ctx, bson.M{
		"timestamp": bson.M{"$lt": cutoff},
	})
	if err != nil {
		return 0, err
	}

	return result.DeletedCount, nil
}

// ClientLogFilter defines filtering options for client log queries
type ClientLogFilter struct {
	DeviceID   string
	DeviceUUID string
	SessionID  *uint32    // nil = all sessions
	Level      string     // Exact level match
	MinLevel   string     // Minimum level (INFO, WARN, ERROR)
	After      time.Time  // Logs after this time
	Before     time.Time  // Logs before this time
}

// getLevelsAtOrAbove returns log levels at or above the given priority
func getLevelsAtOrAbove(minPriority int) []string {
	allLevels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	result := []string{}
	for i := minPriority; i < len(allLevels); i++ {
		result = append(result, allLevels[i])
	}
	return result
}

// CreateClientLogIndexes creates indexes for efficient client log queries
func CreateClientLogIndexes(ctx context.Context) error {
	db := GetMongoDB()
	if db == nil {
		return nil // Skip if MongoDB not enabled
	}

	collection := db.Collection("client_logs")

	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "deviceId", Value: 1},
				{Key: "timestamp", Value: -1},
			},
		},
		{
			Keys: bson.D{
				{Key: "deviceUuid", Value: 1},
				{Key: "timestamp", Value: -1},
			},
		},
		{
			Keys: bson.D{
				{Key: "sessionId", Value: 1},
				{Key: "timestamp", Value: -1},
			},
		},
		{
			Keys: bson.D{
				{Key: "level", Value: 1},
				{Key: "timestamp", Value: -1},
			},
		},
		{
			Keys: bson.D{{Key: "timestamp", Value: -1}},
		},
		// TTL index: auto-delete logs older than 7 days
		{
			Keys:    bson.D{{Key: "receivedAt", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(7 * 24 * 3600),
		},
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	return err
}
