package bolt

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/boltdb/bolt"
	"github.com/easystack/raptor/pkg/storage"
	cmap "github.com/orcaman/concurrent-map/v2"
)

func NewEngine(path string) (*BoltEngine, error) {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to make cni run dir, error is %s", err)
		}
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 10 * time.Second})

	e := &BoltEngine{
		DB: db,
	}

	return e, err
}

type BoltEngine struct {
	*bolt.DB
}

// NewStorage T's kind equal to Z's kink or Z implements T
func NewStorage[T, Z any](name string, e *BoltEngine) (storage storage.Storage[T], err error) {
	err = e.Update(func(tx *bolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists([]byte(name))
		return err
	})

	if err != nil {
		return nil, fmt.Errorf("create storage error: %s", err)
	}
	b := &boltStorage[T, Z]{
		name:   []byte(name),
		m:      cmap.New[T](),
		engine: e,
	}

	err = e.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(name)).ForEach(func(k, v []byte) error {
			value, err := b.decodeData(v)
			if err != nil {
				return err
			}
			b.m.Set(string(k), value)
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("create storage %s error: %s", name, err.Error())
	}

	return b, nil
}

func DeleteStorage(name string, e *BoltEngine) (err error) {
	err = e.Update(func(tx *bolt.Tx) error {
		err = tx.DeleteBucket([]byte(name))
		return err
	})
	return nil
}
