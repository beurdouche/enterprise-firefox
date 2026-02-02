/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * vim: sw=2 ts=2 et lcs=trail\:.,tab\:>~ :
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "KeyStorage.h"

#include "Persist.h"

#include "nsLocalFile.h"
#include "ScopedNSSTypes.h"

#include <iomanip>
#include <sstream>
#include <string>

static std::string ArrayToHexString(const unsigned char* array,
                                    unsigned int length) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char byte : mozilla::Span<const unsigned char>(array, length)) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

namespace mozilla::storage::key {
nsresult GetKeyForPath(const char* aPath, nsCString& key) {
  nsIFile* file = MakeAndAddRef<nsLocalFile>().take();
  nsresult rv = file->InitWithNativePath(nsCString(aPath));
  NS_ENSURE_SUCCESS(rv, rv);

  return GetKeyForFile(file, key);
}

nsresult GetKeyForFile(nsIFile* aFile, nsCString& keyString) {
  nsAutoString profile_path;
  GetCurrentProfilePath(profile_path);

  nsIFile* profile = MakeAndAddRef<nsLocalFile>().take();
  nsresult rv = profile->InitWithPath(profile_path);
  NS_ENSURE_SUCCESS(rv, rv);

  nsAutoCString filename;
  rv = aFile->GetRelativePath(profile, filename);
  NS_ENSURE_SUCCESS(rv, rv);

  UniqueSECItem key(new SECItem());
  rv = FetchOrCreateKey(filename, key.get());
  NS_ENSURE_SUCCESS(rv, rv);

  keyString.AssignASCII(ArrayToHexString(key->data, key->len));

  return NS_OK;
}
}  // namespace mozilla::storage::key
