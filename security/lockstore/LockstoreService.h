/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_security_lockstore_LockstoreService_h
#define mozilla_security_lockstore_LockstoreService_h

#include "nsString.h"
#include "nsTArray.h"

namespace mozilla::security::lockstore {

class LockstoreService final {
 public:
  static LockstoreService* GetSingleton();

  // Keystore operations
  nsresult KeystoreOpen(const nsACString& aProfilePath);
  nsresult KeystoreCreateDek(const nsACString& aCollection, bool aExtractable);
  nsresult KeystoreGetDek(const nsACString& aCollection,
                          nsTArray<uint8_t>& aDek);
  nsresult KeystoreDeleteDek(const nsACString& aCollection, bool* aDeleted);
  nsresult KeystoreListCollections(nsTArray<nsCString>& aCollections);
  nsresult KeystoreClose();

  // Datastore operations
  nsresult DatastoreOpen(const nsACString& aCollection);
  nsresult DatastorePut(const nsACString& aCollection,
                        const nsACString& aEntryName,
                        const nsTArray<uint8_t>& aData);
  nsresult DatastoreGet(const nsACString& aCollection,
                        const nsACString& aEntryName, nsTArray<uint8_t>& aData);
  nsresult DatastoreDelete(const nsACString& aCollection,
                           const nsACString& aEntryName, bool* aDeleted);
  nsresult DatastoreList(const nsACString& aCollection,
                         nsTArray<nsCString>& aEntries);
  nsresult DatastoreClose(const nsACString& aCollection);

  LockstoreService() = default;
  ~LockstoreService() = default;

 private:
  bool IsParentProcess();
};

}  // namespace mozilla::security::lockstore

#endif  // mozilla_security_lockstore_LockstoreService_h
