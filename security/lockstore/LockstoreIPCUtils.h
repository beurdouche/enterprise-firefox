/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_security_lockstore_LockstoreIPCUtils_h
#define mozilla_security_lockstore_LockstoreIPCUtils_h

#include "ipc/IPCMessageUtils.h"
#include "mozilla/security/lockstore/PLockstore.h"

namespace IPC {

template <>
struct ParamTraits<mozilla::security::lockstore::RawBytes> {
  typedef mozilla::security::lockstore::RawBytes paramType;

  static void Write(MessageWriter* aWriter, const paramType& aParam) {
    WriteParam(aWriter, aParam.data());
  }

  static bool Read(MessageReader* aReader, paramType* aResult) {
    return ReadParam(aReader, &aResult->data());
  }
};

template <>
struct ParamTraits<mozilla::security::lockstore::StringList> {
  typedef mozilla::security::lockstore::StringList paramType;

  static void Write(MessageWriter* aWriter, const paramType& aParam) {
    WriteParam(aWriter, aParam.items());
  }

  static bool Read(MessageReader* aReader, paramType* aResult) {
    return ReadParam(aReader, &aResult->items());
  }
};

}  // namespace IPC

#endif  // mozilla_security_lockstore_LockstoreIPCUtils_h
