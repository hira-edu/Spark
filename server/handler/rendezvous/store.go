package rendezvous

import (
	"Rocket/server/common"
	"Rocket/server/storage"
	"context"
	"errors"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type peerStore interface {
	Upsert(*PeerRecord) error
	UpdateHeartbeat(peerID, token string) error
	Lookup(peerID, token string) (*PeerRecord, error)
	LookupByID(peerID string) (*PeerRecord, error) // Lookup without token validation (Phase 3)
	Delete(peerID string) error
}

var (
	storeInit sync.Once
	storeInst peerStore
)

func getPeerStore() peerStore {
	storeInit.Do(func() {
		if storeInst == nil {
			storeInst = initPeerStore()
		}
	})
	return storeInst
}

func initPeerStore() peerStore {
	if storage.IsMongoEnabled() {
		ps, err := newMongoPeerStore(peerTTL)
		if err == nil {
			common.Info(nil, `RENDEZVOUS_STORE`, `mongo`, `using MongoDB-backed peer store`, map[string]any{
				`ttl_seconds`: int(peerTTL.Seconds()),
			})
			return ps
		}
		common.Warn(nil, `RENDEZVOUS_STORE`, `fallback`, err.Error(), nil)
	}

	common.Info(nil, `RENDEZVOUS_STORE`, `memory`, `using in-memory peer store`, map[string]any{
		`ttl_seconds`: int(peerTTL.Seconds()),
	})
	return newMemoryPeerStore(peerTTL)
}

// setPeerStoreForTest overrides the global store (used by tests).
func setPeerStoreForTest(ps peerStore) {
	storeInst = ps
	storeInit = sync.Once{}
}

type memoryPeerStore struct {
	mu    sync.RWMutex
	peers map[string]*PeerRecord
	ttl   time.Duration
}

func newMemoryPeerStore(ttl time.Duration) *memoryPeerStore {
	store := &memoryPeerStore{
		peers: make(map[string]*PeerRecord),
		ttl:   ttl,
	}
	go store.runCleanup()
	return store
}

func (m *memoryPeerStore) runCleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for id, peer := range m.peers {
			if now.Sub(peer.LastSeen) > m.ttl {
				delete(m.peers, id)
			}
		}
		m.mu.Unlock()
	}
}

func (m *memoryPeerStore) Upsert(record *PeerRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers[record.PeerID] = record
	return nil
}

func (m *memoryPeerStore) UpdateHeartbeat(peerID, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.peers[peerID]
	if !ok {
		return errPeerNotFound
	}
	if record.Token != token {
		return errTokenMismatch
	}
	if time.Since(record.LastSeen) > m.ttl {
		delete(m.peers, peerID)
		return errPeerExpired
	}
	record.LastSeen = time.Now()
	return nil
}

func (m *memoryPeerStore) Lookup(peerID, token string) (*PeerRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.peers[peerID]
	if !ok {
		return nil, errPeerNotFound
	}
	if record.Token != token {
		return nil, errTokenMismatch
	}
	if time.Since(record.LastSeen) > m.ttl {
		return nil, errPeerExpired
	}
	return record, nil
}

func (m *memoryPeerStore) LookupByID(peerID string) (*PeerRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.peers[peerID]
	if !ok {
		return nil, errPeerNotFound
	}
	if time.Since(record.LastSeen) > m.ttl {
		return nil, errPeerExpired
	}
	return record, nil
}

func (m *memoryPeerStore) Delete(peerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[peerID]; !ok {
		return errPeerNotFound
	}
	delete(m.peers, peerID)
	return nil
}

// get is used by tests to inspect state.
func (m *memoryPeerStore) get(peerID string) (*PeerRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.peers[peerID]
	return rec, ok
}

type mongoPeerStore struct {
	coll *mongo.Collection
	ttl  time.Duration
}

func newMongoPeerStore(ttl time.Duration) (*mongoPeerStore, error) {
	if !storage.IsMongoEnabled() {
		return nil, errors.New("mongodb disabled")
	}
	db := storage.GetMongoDB()
	if db == nil {
		return nil, errors.New("mongodb not initialized")
	}
	coll := db.Collection("rendezvous_peers")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "peer_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil && !isIndexConflict(err) {
		return nil, err
	}
	ttlSeconds := int32(ttl.Seconds())
	if ttlSeconds <= 0 {
		ttlSeconds = int32(peerTTL.Seconds())
	}
	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "last_seen", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(ttlSeconds),
	}); err != nil && !isIndexConflict(err) {
		return nil, err
	}

	store := &mongoPeerStore{
		coll: coll,
		ttl:  ttl,
	}
	go store.runCleanup()
	return store, nil
}

func (m *mongoPeerStore) runCleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cutoff := time.Now().Add(-m.ttl)
		_, _ = m.coll.DeleteMany(ctx, bson.M{
			"last_seen": bson.M{"$lt": cutoff},
		})
		cancel()
	}
}

func (m *mongoPeerStore) Upsert(record *PeerRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.coll.UpdateOne(
		ctx,
		bson.M{"peer_id": record.PeerID},
		bson.M{
			"$set": bson.M{
				"token":     record.Token,
				"endpoints": record.Endpoints,
				"metadata":  record.Metadata,
				"last_seen": record.LastSeen,
			},
			"$setOnInsert": bson.M{
				"created_at": record.CreatedAt,
			},
		},
		options.Update().SetUpsert(true),
	)
	return err
}

func (m *mongoPeerStore) UpdateHeartbeat(peerID, token string) error {
	if _, err := m.Lookup(peerID, token); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.coll.UpdateOne(ctx, bson.M{"peer_id": peerID}, bson.M{
		"$set": bson.M{"last_seen": time.Now()},
	})
	return err
}

func (m *mongoPeerStore) Lookup(peerID, token string) (*PeerRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var record PeerRecord
	err := m.coll.FindOne(ctx, bson.M{"peer_id": peerID}).Decode(&record)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errPeerNotFound
	}
	if err != nil {
		return nil, err
	}
	if record.Token != token {
		return nil, errTokenMismatch
	}
	if time.Since(record.LastSeen) > m.ttl {
		return nil, errPeerExpired
	}
	return &record, nil
}

func (m *mongoPeerStore) LookupByID(peerID string) (*PeerRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var record PeerRecord
	err := m.coll.FindOne(ctx, bson.M{"peer_id": peerID}).Decode(&record)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errPeerNotFound
	}
	if err != nil {
		return nil, err
	}
	if time.Since(record.LastSeen) > m.ttl {
		return nil, errPeerExpired
	}
	return &record, nil
}

func (m *mongoPeerStore) Delete(peerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := m.coll.DeleteOne(ctx, bson.M{"peer_id": peerID})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return errPeerNotFound
	}
	return nil
}

func isIndexConflict(err error) bool {
	if err == nil {
		return false
	}
	return mongo.IsDuplicateKeyError(err)
}
