// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory implementation of Store, for testing.
type MemStore struct {
	mu            sync.Mutex
	cveRecords    map[string]*CVERecord
	updateRecords map[string]*UpdateRecord
}

// NewMemStore creates a new, empty MemStore.
func NewMemStore() *MemStore {
	m := &MemStore{}
	_ = m.Clear(context.Background())
	return m
}

// Clear removes all data from the MemStore.
func (ms *MemStore) Clear(context.Context) error {
	ms.cveRecords = map[string]*CVERecord{}
	ms.updateRecords = map[string]*UpdateRecord{}
	return nil
}

// CVERecords return all the CVERecords of the store.
func (ms *MemStore) CVERecords() map[string]*CVERecord {
	return ms.cveRecords
}

// CreateUpdateRecord implements Store.CreateUpdateRecord.
func (ms *MemStore) CreateUpdateRecord(ctx context.Context, r *UpdateRecord) error {
	r.ID = fmt.Sprint(rand.Uint32())
	if ms.updateRecords[r.ID] != nil {
		panic("duplicate ID")
	}
	r.UpdatedAt = time.Now()
	return ms.SetUpdateRecord(ctx, r)
}

// SetUpdateRecord implements Store.SetUpdateRecord.
func (ms *MemStore) SetUpdateRecord(_ context.Context, r *UpdateRecord) error {
	if r.ID == "" {
		return errors.New("SetUpdateRecord: need ID")
	}
	c := *r
	c.UpdatedAt = time.Now()
	ms.updateRecords[c.ID] = &c
	return nil
}

// ListUpdateRecords implements Store.ListUpdateRecords.
func (ms *MemStore) ListUpdateRecords(context.Context) ([]*UpdateRecord, error) {
	var urs []*UpdateRecord
	for _, ur := range ms.updateRecords {
		urs = append(urs, ur)
	}
	sort.Slice(urs, func(i, j int) bool {
		return urs[i].StartedAt.After(urs[j].StartedAt)
	})
	return urs, nil
}

// RunTransaction implements Store.RunTransaction.
// A transaction runs with a single lock on the entire DB.
func (ms *MemStore) RunTransaction(ctx context.Context, f func(context.Context, Transaction) error) error {
	tx := &memTransaction{ms}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return f(ctx, tx)
}

// memTransaction implements Store.Transaction.
type memTransaction struct {
	ms *MemStore
}

// CreateCVERecord implements Transaction.CreateCVERecord.
func (tx *memTransaction) CreateCVERecord(r *CVERecord) error {
	if err := r.Validate(); err != nil {
		return err
	}
	tx.ms.cveRecords[r.ID] = r
	return nil
}

// SetCVERecord implements Transaction.SetCVERecord.
func (tx *memTransaction) SetCVERecord(r *CVERecord) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if tx.ms.cveRecords[r.ID] == nil {
		return fmt.Errorf("CVERecord with ID %q not found", r.ID)
	}
	tx.ms.cveRecords[r.ID] = r
	return nil
}

// GetCVERecords implements Transaction.GetCVERecords.
func (tx *memTransaction) GetCVERecords(startID, endID string) ([]*CVERecord, error) {
	var crs []*CVERecord
	for id, r := range tx.ms.cveRecords {
		if id >= startID && id <= endID {
			c := *r
			crs = append(crs, &c)
		}
	}
	// Sort for testing.
	sort.Slice(crs, func(i, j int) bool {
		return crs[i].ID < crs[j].ID
	})
	return crs, nil
}
