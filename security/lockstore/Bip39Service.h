/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_security_lockstore_Bip39Service_h
#define mozilla_security_lockstore_Bip39Service_h

#include "nsIBip39.h"

namespace mozilla::security::lockstore {

class Bip39Service final : public nsIBip39 {
 public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSIBIP39

  Bip39Service() = default;

 private:
  ~Bip39Service() = default;
};

}  // namespace mozilla::security::lockstore

#endif  // mozilla_security_lockstore_Bip39Service_h
