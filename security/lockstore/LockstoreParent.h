/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_security_lockstore_LockstoreParent_h
#define mozilla_security_lockstore_LockstoreParent_h

#include "mozilla/security/lockstore/PLockstore.h"
#include "mozilla/security/lockstore/PLockstoreParent.h"

namespace mozilla::security::lockstore {

class LockstoreParent final : public PLockstoreParent {
 public:
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(LockstoreParent, override);

  LockstoreParent() = default;

  void ActorDestroy(ActorDestroyReason aReason) override;

  // Keystore operations
  mozilla::ipc::IPCResult RecvRequestKeystoreOpen(
      const nsACString& aProfilePath, RequestKeystoreOpenResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestKeystoreCreateDek(
      const nsACString& aCollection,
      RequestKeystoreCreateDekResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestKeystoreDeleteDek(
      const nsACString& aCollection,
      RequestKeystoreDeleteDekResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestKeystoreListCollections(
      RequestKeystoreListCollectionsResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestKeystoreClose(
      RequestKeystoreCloseResolver&& aResolver);

  // Datastore operations
  mozilla::ipc::IPCResult RecvRequestDatastoreOpen(
      const nsACString& aCollection, RequestDatastoreOpenResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestDatastorePut(
      const nsACString& aCollection, const nsACString& aEntryName,
      const nsTArray<uint8_t>& aData, RequestDatastorePutResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestDatastoreGet(
      const nsACString& aCollection, const nsACString& aEntryName,
      RequestDatastoreGetResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestDatastoreDelete(
      const nsACString& aCollection, const nsACString& aEntryName,
      RequestDatastoreDeleteResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestDatastoreList(
      const nsACString& aCollection, RequestDatastoreListResolver&& aResolver);

  mozilla::ipc::IPCResult RecvRequestDatastoreClose(
      const nsACString& aCollection, RequestDatastoreCloseResolver&& aResolver);

 protected:
  ~LockstoreParent() = default;
};

}  // namespace mozilla::security::lockstore

#endif  // mozilla_security_lockstore_LockstoreParent_h
