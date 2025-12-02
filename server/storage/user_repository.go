package storage

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// User represents an admin user
type User struct {
	ID           string    `bson:"_id" json:"id"`
	Username     string    `bson:"username" json:"username"`
	PasswordHash string    `bson:"passwordHash" json:"-"` // Never expose in JSON
	Role         string    `bson:"role" json:"role"`      // admin, user, etc.
	Email        string    `bson:"email" json:"email"`
	CreatedAt    time.Time `bson:"createdAt" json:"createdAt"`
	UpdatedAt    time.Time `bson:"updatedAt" json:"updatedAt"`
	LastLoginAt  time.Time `bson:"lastLoginAt,omitempty" json:"lastLoginAt,omitempty"`
	LastLoginIP  string    `bson:"lastLoginIP,omitempty" json:"lastLoginIP,omitempty"`
	Enabled      bool      `bson:"enabled" json:"enabled"` // Can disable users
}

// UserRepository handles user persistence
type UserRepository struct {
	col *mongo.Collection
}

// NewUserRepository creates a new user repository
func NewUserRepository() *UserRepository {
	return &UserRepository{
		col: GetCollection("users"),
	}
}

// CreateUser creates a new user with hashed password
func (r *UserRepository) CreateUser(ctx context.Context, username, password, role, email string) (*User, error) {
	if r.col == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	// Hash password with bcrypt
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		ID:           username, // Use username as ID for simplicity
		Username:     username,
		PasswordHash: string(passwordHash),
		Role:         role,
		Email:        email,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Enabled:      true,
	}

	_, err = r.col.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, fmt.Errorf("username already exists")
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// GetUser retrieves a user by username
func (r *UserRepository) GetUser(ctx context.Context, username string) (*User, error) {
	if r.col == nil {
		return nil, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	var user User
	err := r.col.FindOne(ctx, bson.M{"_id": username}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// ValidatePassword checks if the provided password matches the user's password
func (r *UserRepository) ValidatePassword(ctx context.Context, username, password string) (*User, error) {
	user, err := r.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if !user.Enabled {
		return nil, fmt.Errorf("user is disabled")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}

// UpdateLastLogin updates the user's last login timestamp and IP
func (r *UserRepository) UpdateLastLogin(ctx context.Context, username, ip string) error {
	if r.col == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"lastLoginAt": time.Now(),
			"lastLoginIP": ip,
		},
	}

	_, err := r.col.UpdateOne(ctx, bson.M{"_id": username}, update)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// UpdatePassword updates a user's password
func (r *UserRepository) UpdatePassword(ctx context.Context, username, newPassword string) error {
	if r.col == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	// Hash new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	update := bson.M{
		"$set": bson.M{
			"passwordHash": string(passwordHash),
			"updatedAt":    time.Now(),
		},
	}

	result, err := r.col.UpdateOne(ctx, bson.M{"_id": username}, update)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ListUsers returns all users (paginated)
func (r *UserRepository) ListUsers(ctx context.Context, limit, skip int) ([]*User, error) {
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
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer cursor.Close(ctx)

	var users []*User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, fmt.Errorf("failed to decode users: %w", err)
	}

	return users, nil
}

// CountUsers returns the total number of users
func (r *UserRepository) CountUsers(ctx context.Context) (int64, error) {
	if r.col == nil {
		return 0, fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	count, err := r.col.CountDocuments(ctx, bson.M{})
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// DeleteUser removes a user
func (r *UserRepository) DeleteUser(ctx context.Context, username string) error {
	if r.col == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	_, err := r.col.DeleteOne(ctx, bson.M{"_id": username})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// UpdateUser updates user fields (except password)
func (r *UserRepository) UpdateUser(ctx context.Context, username string, updates map[string]interface{}) error {
	if r.col == nil {
		return fmt.Errorf("MongoDB not initialized")
	}

	ctx, cancel := WithTimeout(ctx)
	defer cancel()

	// Prevent updating sensitive fields directly
	delete(updates, "passwordHash")
	delete(updates, "_id")
	delete(updates, "username")
	delete(updates, "createdAt")

	// Add updatedAt timestamp
	updates["updatedAt"] = time.Now()

	update := bson.M{"$set": updates}

	result, err := r.col.UpdateOne(ctx, bson.M{"_id": username}, update)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}
