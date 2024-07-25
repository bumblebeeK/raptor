package bolt

import (
	"encoding/json"
	"reflect"

	"github.com/boltdb/bolt"
	"github.com/easystack/raptor/pkg/base"
	"github.com/easystack/raptor/pkg/storage"
	cmap "github.com/orcaman/concurrent-map/v2"
)

var log = base.NewLogWithField("sub_sys", "storage")

type KeyNotFoundErr struct {
	error
}

type boltStorage[T, Z any] struct {
	name   []byte
	engine *BoltEngine
	m      cmap.ConcurrentMap[string, T]
}

func (s *boltStorage[T, Z]) Put(key string, value T) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return s.engine.Update(func(tx *bolt.Tx) error {
		err = tx.Bucket(s.name).Put([]byte(key), data)
		if err == nil {
			s.m.Set(key, value)
		}
		return err
	})

}
func (s *boltStorage[T, Z]) Get(key string) (data T, err error) {

	value, ok := s.m.Get(key)
	if !ok {
		err = KeyNotFoundErr{}
		return
	}

	return value, nil
}

func (s *boltStorage[T, Z]) Delete(key string) (T, error) {
	var err error
	var data T
	data, err = s.Get(key)
	if err != nil {
		return data, err
	}

	return data, s.engine.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(s.name)
		err := b.Delete([]byte(key))
		if err == nil {
			s.m.Remove(key)
		}
		return err
	})
}

func (s *boltStorage[T, Z]) Count() int {
	return s.m.Count()

}

func (s *boltStorage[T, Z]) decodeData(data []byte) (value T, err error) {
	var t T
	var z Z
	if reflect.TypeOf(t) == reflect.TypeOf(z) {
		err = json.Unmarshal(data, &value)
		return
	}
	val := reflect.New(reflect.TypeOf(z)).Interface()
	err = json.Unmarshal(data, &(val))
	return val.(T), nil

}

func (s *boltStorage[T, Z]) List() []storage.KV[T] {
	var ans []storage.KV[T]
	for key, item := range s.m.Items() {
		ans = append(ans, storage.KV[T]{
			Key:   key,
			Value: item,
		})
	}

	return ans
}
