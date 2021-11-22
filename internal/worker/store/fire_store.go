// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"errors"
	"sort"

	"cloud.google.com/go/firestore"
	"golang.org/x/vuln/internal/derrors"
	"google.golang.org/api/iterator"
)

// FireStore is a Store implemented with Google Cloud Firestore.
//
// A Firestore DB is a set of documents. Each document has its own unique ID
// (primary key). Documents are grouped into collections, and each document can
// have sub-collections. A document can be referred to by a path of the form
// top-level-collection/doc/sub-collection/doc/...
//
// In this layout, there is a single top-level collection called Namespaces,
// with documents for each development environment. Within each namespace, there
// are two collections: CVEs for CVERecords, and Updates for UpdateRecords.
type FireStore struct {
	namespace string
	client    *firestore.Client
	nsDoc     *firestore.DocumentRef
}

const (
	namespaceCollection = "Namespaces"
	updateCollection    = "Updates"
	cveCollection       = "CVEs"
)

// NewFireStore creates a new FireStore, backed by a client to Firestore. Since
// each project can have only one Firestore database, callers must provide a
// non-empty namespace to distinguish different virtual databases (e.g. prod and
// testing).
func NewFireStore(ctx context.Context, projectID, namespace string) (_ *FireStore, err error) {
	defer derrors.Wrap(&err, "NewFireStore(%q, %q)", projectID, namespace)

	if namespace == "" {
		return nil, errors.New("empty namespace")
	}
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &FireStore{
		namespace: namespace,
		client:    client,
		nsDoc:     client.Collection(namespaceCollection).Doc(namespace),
	}, nil
}

// CreateUpdateRecord implements Store.CreateUpdateRecord.
// On successful return, r.ID is set to the record's ID.
func (fs *FireStore) CreateUpdateRecord(ctx context.Context, r *UpdateRecord) (err error) {
	defer derrors.Wrap(&err, "CreateUpdateRecord()")

	docref := fs.nsDoc.Collection(updateCollection).NewDoc()
	if _, err := docref.Create(ctx, r); err != nil {
		return err
	}
	r.ID = docref.ID
	return nil
}

// SetUpdateRecord implements Store.SetUpdateRecord.
func (fs *FireStore) SetUpdateRecord(ctx context.Context, r *UpdateRecord) (err error) {
	defer derrors.Wrap(&err, "SetUpdateRecord(%q)", r.ID)

	if r.ID == "" {
		return errors.New("missing ID")
	}
	_, err = fs.nsDoc.Collection(updateCollection).Doc(r.ID).Set(ctx, r)
	return err
}

// ListUpdateRecords implements Store.ListUpdateRecords.
func (fs *FireStore) ListUpdateRecords(ctx context.Context) ([]*UpdateRecord, error) {
	var urs []*UpdateRecord
	iter := fs.nsDoc.Collection(updateCollection).Documents(ctx)
	for {
		docsnap, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var ur UpdateRecord
		if err := docsnap.DataTo(&ur); err != nil {
			return nil, err
		}
		ur.ID = docsnap.Ref.ID
		urs = append(urs, &ur)
	}
	sort.Slice(urs, func(i, j int) bool {
		return urs[i].StartedAt.After(urs[j].StartedAt)
	})
	return urs, nil
}

// RunTransaction implements Store.RunTransaction.
func (fs *FireStore) RunTransaction(ctx context.Context, f func(context.Context, Transaction) error) error {
	return fs.client.RunTransaction(ctx,
		func(ctx context.Context, tx *firestore.Transaction) error {
			return f(ctx, &fsTransaction{fs, tx})
		})
}

// cveRecordRef returns a DocumentRef to the CVERecord with id.
func (s *FireStore) cveRecordRef(id string) *firestore.DocumentRef {
	return s.nsDoc.Collection(cveCollection).Doc(id)
}

// fsTransaction implements Transaction
type fsTransaction struct {
	s *FireStore
	t *firestore.Transaction
}

// CreateCVERecord implements Transaction.CreateCVERecord.
func (tx *fsTransaction) CreateCVERecord(r *CVERecord) (err error) {
	defer derrors.Wrap(&err, "FireStore.CreateCVERecord(%s)", r.ID)

	if err := r.Validate(); err != nil {
		return err
	}
	return tx.t.Create(tx.s.cveRecordRef(r.ID), r)
}

// SetCVERecord implements Transaction.SetCVERecord.
func (tx *fsTransaction) SetCVERecord(r *CVERecord) (err error) {
	defer derrors.Wrap(&err, "SetCVERecord(%s)", r.ID)

	if err := r.Validate(); err != nil {
		return err
	}
	return tx.t.Set(tx.s.cveRecordRef(r.ID), r)
}

// GetCVERecords implements Transaction.GetCVERecords.
func (tx *fsTransaction) GetCVERecords(startID, endID string) (_ []*CVERecord, err error) {
	defer derrors.Wrap(&err, "GetCVERecords(%s, %s)", startID, endID)

	q := tx.s.nsDoc.Collection(cveCollection).
		OrderBy(firestore.DocumentID, firestore.Asc).
		StartAt(startID).
		EndAt(endID)
	iter := tx.t.Documents(q)
	docsnaps, err := iter.GetAll()
	if err != nil {
		return nil, err
	}
	var crs []*CVERecord
	for _, ds := range docsnaps {
		var cr CVERecord
		if err := ds.DataTo(&cr); err != nil {
			return nil, err
		}
		crs = append(crs, &cr)
	}
	return crs, nil
}

// Clear removes all documents in the namespace.
func (s *FireStore) Clear(ctx context.Context) (err error) {
	defer derrors.Wrap(&err, "Clear")

	collrefs, err := s.nsDoc.Collections(ctx).GetAll()
	if err != nil {
		return err
	}
	for _, cr := range collrefs {
		if err := deleteCollection(ctx, s.client, cr, 100); err != nil {
			return err
		}
	}
	return nil
}

// Copied from https://cloud.google.com/firestore/docs/samples/firestore-data-delete-collection.
func deleteCollection(ctx context.Context, client *firestore.Client, ref *firestore.CollectionRef, batchSize int) error {
	for {
		// Get a batch of documents
		iter := ref.Limit(batchSize).Documents(ctx)
		numDeleted := 0

		// Iterate through the documents, adding a delete operation for each one
		// to a WriteBatch.
		batch := client.Batch()
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}
			batch.Delete(doc.Ref)
			numDeleted++
		}

		// If there are no documents to delete, the process is over.
		if numDeleted == 0 {
			return nil
		}

		if _, err := batch.Commit(ctx); err != nil {
			return err
		}
	}
}
