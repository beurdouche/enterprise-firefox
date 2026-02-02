/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "LockstoreParent.h"

#include "mozilla/security/lockstore/lockstore_ffi_generated.h"
#include "nsTArray.h"
#include "nsString.h"

namespace mozilla::security::lockstore {

void LockstoreParent::ActorDestroy(ActorDestroyReason aReason) {}

// Keystore operations

mozilla::ipc::IPCResult LockstoreParent::RecvRequestKeystoreOpen(
    const nsACString& aProfilePath, RequestKeystoreOpenResolver&& aResolver) {
  nsCString profilePath(aProfilePath);
  nsresult rv = lockstore_keystore_open(&profilePath);
  aResolver(rv);
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestKeystoreCreateDek(
    const nsACString& aCollection, bool aExtractable,
    RequestKeystoreCreateDekResolver&& aResolver) {
  nsCString collection(aCollection);
  nsresult rv = lockstore_keystore_create_dek(
      &collection, LockstoreSecurityLevel::LocalKey, aExtractable);
  aResolver(rv);
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestKeystoreGetDek(
    const nsACString& aCollection, RequestKeystoreGetDekResolver&& aResolver) {
  nsCString collection(aCollection);
  nsTArray<uint8_t> dek;
  nsresult rv = lockstore_keystore_get_dek(&collection, &dek);
  if (NS_FAILED(rv)) {
    aResolver(std::make_tuple(rv, mozilla::Maybe<RawBytes>()));
    return IPC_OK();
  }
  RawBytes rawBytes;
  rawBytes.data().AppendElements(dek.Elements(), dek.Length());
  aResolver(std::make_tuple(rv, mozilla::Some(std::move(rawBytes))));
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestKeystoreDeleteDek(
    const nsACString& aCollection,
    RequestKeystoreDeleteDekResolver&& aResolver) {
  nsCString collection(aCollection);
  bool deleted = false;
  nsresult rv = lockstore_keystore_delete_dek(&collection, &deleted);
  aResolver(std::make_tuple(rv, deleted));
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestKeystoreListCollections(
    RequestKeystoreListCollectionsResolver&& aResolver) {
  nsTArray<nsCString> collections;
  nsresult rv = lockstore_keystore_list_collections(&collections);

  StringList result;
  for (const auto& item : collections) {
    result.items().AppendElement(item);
  }
  aResolver(std::make_tuple(rv, result));
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestKeystoreClose(
    RequestKeystoreCloseResolver&& aResolver) {
  nsresult rv = lockstore_keystore_close();
  aResolver(rv);
  return IPC_OK();
}

// Datastore operations

mozilla::ipc::IPCResult LockstoreParent::RecvRequestDatastoreOpen(
    const nsACString& aCollection, RequestDatastoreOpenResolver&& aResolver) {
  nsCString collection(aCollection);
  nsresult rv = lockstore_datastore_open(&collection);
  aResolver(rv);
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestDatastorePut(
    const nsACString& aCollection, const nsACString& aEntryName,
    const nsTArray<uint8_t>& aData, RequestDatastorePutResolver&& aResolver) {
  nsCString collection(aCollection);
  nsCString entryName(aEntryName);
  nsresult rv = lockstore_datastore_put(&collection, &entryName,
                                        aData.Elements(), aData.Length());
  aResolver(rv);
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestDatastoreGet(
    const nsACString& aCollection, const nsACString& aEntryName,
    RequestDatastoreGetResolver&& aResolver) {
  nsCString collection(aCollection);
  nsCString entryName(aEntryName);
  nsTArray<uint8_t> data;
  nsresult rv = lockstore_datastore_get(&collection, &entryName, &data);
  if (NS_FAILED(rv)) {
    mozilla::Maybe<RawBytes> none;
    aResolver(std::make_tuple(rv, none));
    return IPC_OK();
  }

  RawBytes rawBytes;
  rawBytes.data().AppendElements(data.Elements(), data.Length());
  mozilla::Maybe<RawBytes> result = Some(std::move(rawBytes));
  aResolver(std::make_tuple(rv, result));
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestDatastoreDelete(
    const nsACString& aCollection, const nsACString& aEntryName,
    RequestDatastoreDeleteResolver&& aResolver) {
  nsCString collection(aCollection);
  nsCString entryName(aEntryName);
  bool deleted = false;
  nsresult rv = lockstore_datastore_delete(&collection, &entryName, &deleted);
  aResolver(std::make_tuple(rv, deleted));
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestDatastoreList(
    const nsACString& aCollection, RequestDatastoreListResolver&& aResolver) {
  nsCString collection(aCollection);
  nsTArray<nsCString> entries;
  nsresult rv = lockstore_datastore_list(&collection, &entries);

  StringList result;
  for (const auto& item : entries) {
    result.items().AppendElement(item);
  }
  aResolver(std::make_tuple(rv, result));
  return IPC_OK();
}

mozilla::ipc::IPCResult LockstoreParent::RecvRequestDatastoreClose(
    const nsACString& aCollection, RequestDatastoreCloseResolver&& aResolver) {
  nsCString collection(aCollection);
  nsresult rv = lockstore_datastore_close(&collection);
  aResolver(rv);
  return IPC_OK();
}

}  // namespace mozilla::security::lockstore
