/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package snapshot

import (
	"testing"
	"time"

	snapshot "github.com/containerd/containerd/snapshots"
	assertlib "github.com/stretchr/testify/assert"

	"github.com/containerd/cri/pkg/store"
)

func TestSnapshotStore(t *testing.T) {
	snapshots := map[string]Snapshot{
		"key1": {
			Key:       "key1",
			Kind:      snapshot.KindActive,
			Size:      10,
			Inodes:    100,
			Timestamp: time.Now().UnixNano(),
		},
		"key2": {
			Key:       "key2",
			Kind:      snapshot.KindCommitted,
			Size:      20,
			Inodes:    200,
			Timestamp: time.Now().UnixNano(),
		},
		"key3": {
			Key:       "key3",
			Kind:      snapshot.KindView,
			Size:      0,
			Inodes:    0,
			Timestamp: time.Now().UnixNano(),
		},
	}
	assert := assertlib.New(t)

	s := NewStore()

	t.Logf("should be able to add snapshot")
	for _, sn := range snapshots {
		s.Add(sn)
	}

	t.Logf("should be able to get snapshot")
	for id, sn := range snapshots {
		got, err := s.Get(id)
		assert.NoError(err)
		assert.Equal(sn, got)
	}

	t.Logf("should be able to list snapshot")
	sns := s.List()
	assert.Len(sns, 3)

	testKey := "key2"

	t.Logf("should be able to delete snapshot")
	s.Delete(testKey)
	sns = s.List()
	assert.Len(sns, 2)

	t.Logf("get should return empty struct and ErrNotExist after deletion")
	sn, err := s.Get(testKey)
	assert.Equal(Snapshot{}, sn)
	assert.Equal(store.ErrNotExist, err)
}
