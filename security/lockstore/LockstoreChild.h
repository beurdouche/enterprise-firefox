/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_security_lockstore_LockstoreChild_h
#define mozilla_security_lockstore_LockstoreChild_h

#include "mozilla/security/lockstore/PLockstore.h"
#include "mozilla/security/lockstore/PLockstoreChild.h"

namespace mozilla::security::lockstore {

class LockstoreChild final : public PLockstoreChild {
 public:
  NS_INLINE_DECL_REFCOUNTING(LockstoreChild, override)

  LockstoreChild() = default;

 protected:
  ~LockstoreChild() = default;
};

}  // namespace mozilla::security::lockstore

#endif  // mozilla_security_lockstore_LockstoreChild_h
