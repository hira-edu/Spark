package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoClient  *mongo.Client
	mongoDB      *mongo.Database
	mongoEnabled bool
	mongoCtx     = context.Background()
	mongoTimeout = 10 * time.Second
)

// InitMongoDB initializes MongoDB connection
func InitMongoDB(uri, database string) error {
	if uri == "" || database == "" {
		return fmt.Errorf("MongoDB URI and database name are required")
	}

	ctx, cancel := context.WithTimeout(mongoCtx, mongoTimeout)
	defer cancel()

	clientOptions := options.Client().
		ApplyURI(uri).
		SetMaxPoolSize(50).
		SetMinPoolSize(10).
		SetMaxConnIdleTime(30 * time.Second).
		SetServerSelectionTimeout(5 * time.Second)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	mongoClient = client
	mongoDB = client.Database(database)
	mongoEnabled = true

	// Create indexes
	if err := createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

// createIndexes creates necessary indexes for collections
func createIndexes(ctx context.Context) error {
	// Users collection indexes
	usersCol := mongoDB.Collection("users")
	userIndexes := []mongo.IndexModel{
		// Username index (unique, primary key)
		{
			Keys: bson.D{{Key: "username", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("username_1"),
		},
		// Email index (unique, for future email-based features)
		{
			Keys: bson.D{{Key: "email", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetSparse(true). // Allow null emails
				SetName("email_1"),
		},
	}

	_, err := usersCol.Indexes().CreateMany(ctx, userIndexes)
	if err != nil {
		return fmt.Errorf("failed to create users indexes: %w", err)
	}

	// Shares collection indexes
	sharesCol := mongoDB.Collection("shares")

	indexes := []mongo.IndexModel{
		// Token index for fast lookup (unique)
		{
			Keys: bson.D{{Key: "token", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("token_1"),
		},
		// Device index for querying shares by device
		{
			Keys: bson.D{{Key: "device", Value: 1}},
			Options: options.Index().
				SetName("device_1"),
		},
		// ExpiresAt index for cleanup queries
		{
			Keys: bson.D{{Key: "expiresAt", Value: 1}},
			Options: options.Index().
				SetName("expiresAt_1"),
		},
		// Compound index for active shares lookup
		{
			Keys: bson.D{
				{Key: "device", Value: 1},
				{Key: "expiresAt", Value: 1},
			},
			Options: options.Index().
				SetName("device_expiresAt_1"),
		},
		// CreatedBy index for admin audit
		{
			Keys: bson.D{{Key: "createdBy", Value: 1}},
			Options: options.Index().
				SetName("createdBy_1"),
		},
	}

	_, err = sharesCol.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create shares indexes: %w", err)
	}

	// Rate limit collection indexes
	rateLimitCol := mongoDB.Collection("rate_limits")
	rateLimitIndexes := []mongo.IndexModel{
		// IP index with TTL for auto-cleanup
		{
			Keys: bson.D{{Key: "ip", Value: 1}},
			Options: options.Index().
				SetUnique(true).
				SetName("ip_1"),
		},
		// TTL index to auto-delete old entries (1 hour)
		{
			Keys: bson.D{{Key: "expiresAt", Value: 1}},
			Options: options.Index().
				SetExpireAfterSeconds(0).
				SetName("expiresAt_ttl"),
		},
	}

	_, err = rateLimitCol.Indexes().CreateMany(ctx, rateLimitIndexes)
	if err != nil {
		return fmt.Errorf("failed to create rate_limits indexes: %w", err)
	}

	// Controllers collection indexes
	controllerIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "lastSeen", Value: 1}},
			Options: options.Index().SetName("lastSeen_1"),
		},
	}
	if _, err := mongoDB.Collection(controllersCollection).Indexes().CreateMany(ctx, controllerIndexes); err != nil {
		return fmt.Errorf("failed to create controllers indexes: %w", err)
	}

	// Devices collection indexes
	deviceIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "controllerId", Value: 1}},
			Options: options.Index().SetName("controllerId_1"),
		},
		{
			Keys:    bson.D{{Key: "lastSeen", Value: 1}},
			Options: options.Index().SetName("lastSeen_1"),
		},
		{
			Keys:    bson.D{{Key: "leaseExpiresAt", Value: 1}},
			Options: options.Index().SetName("leaseExpiresAt_1"),
		},
	}
	if _, err := mongoDB.Collection(devicesCollection).Indexes().CreateMany(ctx, deviceIndexes); err != nil {
		return fmt.Errorf("failed to create devices indexes: %w", err)
	}

	// Sessions collection indexes
	sessionIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "deviceId", Value: 1}},
			Options: options.Index().SetName("deviceId_1"),
		},
		{
			Keys:    bson.D{{Key: "controllerId", Value: 1}},
			Options: options.Index().SetName("controllerId_1"),
		},
		{
			Keys:    bson.D{{Key: "leaseExpiresAt", Value: 1}},
			Options: options.Index().SetName("leaseExpiresAt_1"),
		},
		{
			Keys:    bson.D{{Key: "state", Value: 1}},
			Options: options.Index().SetName("state_1"),
		},
	}
	if _, err := mongoDB.Collection(sessionsCollection).Indexes().CreateMany(ctx, sessionIndexes); err != nil {
		return fmt.Errorf("failed to create sessions indexes: %w", err)
	}

	// Audits collection indexes
	auditIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "ts", Value: 1}},
			Options: options.Index().SetName("ts_1"),
		},
	}
	if _, err := mongoDB.Collection(auditsCollection).Indexes().CreateMany(ctx, auditIndexes); err != nil {
		return fmt.Errorf("failed to create audits indexes: %w", err)
	}

	// Client logs collection indexes
	if err := CreateClientLogIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create client_logs indexes: %w", err)
	}

	// Auth sessions collection indexes (for persistent login sessions)
	if err := CreateAuthSessionIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create auth_sessions indexes: %w", err)
	}

	return nil
}

// CloseMongoDB closes MongoDB connection
func CloseMongoDB() error {
	if mongoClient != nil {
		ctx, cancel := context.WithTimeout(mongoCtx, mongoTimeout)
		defer cancel()
		return mongoClient.Disconnect(ctx)
	}
	return nil
}

// IsMongoEnabled returns whether MongoDB is enabled
func IsMongoEnabled() bool {
	return mongoEnabled
}

// GetMongoClient returns the MongoDB client
func GetMongoClient() *mongo.Client {
	return mongoClient
}

// GetMongoDB returns the MongoDB database
func GetMongoDB() *mongo.Database {
	return mongoDB
}

// GetCollection returns a MongoDB collection
func GetCollection(name string) *mongo.Collection {
	if mongoDB == nil {
		return nil
	}
	return mongoDB.Collection(name)
}

// WithTimeout creates a context with timeout
func WithTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = mongoCtx
	}
	return context.WithTimeout(parent, mongoTimeout)
}
