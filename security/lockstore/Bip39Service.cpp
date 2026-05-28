/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Bip39Service.h"

#include "mozilla/security/lockstore/lockstore_ffi_generated.h"
#include "nsString.h"

namespace mozilla::security::lockstore {

NS_IMPL_ISUPPORTS(Bip39Service, nsIBip39)

NS_IMETHODIMP
Bip39Service::Generate(uint32_t aWordCount, nsACString& aPhrase) {
  nsAutoCString out;
  nsresult rv = lockstore_bip39_generate(aWordCount, &out);
  if (NS_FAILED(rv)) {
    return rv;
  }
  aPhrase = out;
  return NS_OK;
}

NS_IMETHODIMP
Bip39Service::Validate(const nsACString& aPhrase) {
  return lockstore_bip39_validate(&aPhrase);
}

}  // namespace mozilla::security::lockstore
