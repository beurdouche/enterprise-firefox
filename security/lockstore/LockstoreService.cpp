/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "LockstoreService.h"

#include "mozilla/ClearOnShutdown.h"
#include "mozilla/StaticMutex.h"
#include "mozilla/StaticPtr.h"
#include "nsXULAppAPI.h"

#include "mozilla/security/lockstore/lockstore_ffi_generated.h"

namespace mozilla::security::lockstore {

static StaticAutoPtr<LockstoreService> sSingleton;
static StaticMutex sInitMutex MOZ_UNANNOTATED;

LockstoreService* LockstoreService::GetSingleton() {
  StaticMutexAutoLock lock(sInitMutex);
  if (!sSingleton) {
    sSingleton = new LockstoreService();
    ClearOnShutdown(&sSingleton);
  }
  return sSingleton;
}

bool LockstoreService::IsParentProcess() { return XRE_IsParentProcess(); }

nsresult LockstoreService::KeystoreOpen(const nsACString& aProfilePath) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString path(aProfilePath);
  return lockstore_keystore_open(&path);
}

nsresult LockstoreService::KeystoreCreateDek(const nsACString& aCollection,
                                             bool aExtractable) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  return lockstore_keystore_create_dek(&coll, LockstoreSecurityLevel::LocalKey,
                                       aExtractable);
}

nsresult LockstoreService::KeystoreGetDek(const nsACString& aCollection,
                                          nsTArray<uint8_t>& aDek) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  return lockstore_keystore_get_dek(&coll, &aDek);
}

nsresult LockstoreService::KeystoreDeleteDek(const nsACString& aCollection,
                                             bool* aDeleted) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  return lockstore_keystore_delete_dek(&coll, aDeleted);
}

nsresult LockstoreService::KeystoreListCollections(
    nsTArray<nsCString>& aCollections) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  return lockstore_keystore_list_collections(&aCollections);
}

nsresult LockstoreService::KeystoreClose() {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  return lockstore_keystore_close();
}

nsresult LockstoreService::DatastoreOpen(const nsACString& aCollection) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  return lockstore_datastore_open(&coll);
}

nsresult LockstoreService::DatastorePut(const nsACString& aCollection,
                                        const nsACString& aEntryName,
                                        const nsTArray<uint8_t>& aData) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  nsCString entry(aEntryName);
  return lockstore_datastore_put(&coll, &entry, aData.Elements(),
                                 aData.Length());
}

nsresult LockstoreService::DatastoreGet(const nsACString& aCollection,
                                        const nsACString& aEntryName,
                                        nsTArray<uint8_t>& aData) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  nsCString entry(aEntryName);
  return lockstore_datastore_get(&coll, &entry, &aData);
}

nsresult LockstoreService::DatastoreDelete(const nsACString& aCollection,
                                           const nsACString& aEntryName,
                                           bool* aDeleted) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  nsCString entry(aEntryName);
  return lockstore_datastore_delete(&coll, &entry, aDeleted);
}

nsresult LockstoreService::DatastoreList(const nsACString& aCollection,
                                         nsTArray<nsCString>& aEntries) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  return lockstore_datastore_list(&coll, &aEntries);
}

nsresult LockstoreService::DatastoreClose(const nsACString& aCollection) {
  if (!IsParentProcess()) {
    return NS_ERROR_NOT_IMPLEMENTED;
  }
  nsCString coll(aCollection);
  return lockstore_datastore_close(&coll);
}

}  // namespace mozilla::security::lockstore
