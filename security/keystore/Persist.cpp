/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * vim: sw=2 ts=2 et lcs=trail\:.,tab\:>~ :
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Persist.h"

#include "mozilla/StaticMutex.h"
#include "mozilla/Base64.h"
#include "mozilla/MozPromise.h"
#include "mozilla/gtest/WaitFor.h"
#include "nsAppDirectoryServiceDefs.h"
#include "nsCOMPtr.h"
#include "nsTHashMap.h"
#include "nsThreadUtils.h"
#include "nsHashtablesFwd.h"
#include "nsIToolkitProfileService.h"
#include "nsIFile.h"
#include "nsIProperties.h"
#include "nsNSSHelper.h"
#include "NSSErrorsService.h"
#include "nsServiceManagerUtils.h"
#include "pk11sdr.h"
#include "prerror.h"
#include "prio.h"
#include "ScopedNSSTypes.h"

#define KEYSTORE_MAGIC "# mozilla secure key storage\n"
#define SYSTEM_KEY_NAME "system"

struct Key {
  mozilla::UniqueSECItem key;
  mozilla::UniqueSECItem iv;
};

static mozilla::StaticMutex KEY_MUTEX;
MOZ_RUNINIT static nsTHashMap<nsCString, Key> KEY_MAP;
static constinit mozilla::UniquePK11SymKey SYSTEM_KEY;

nsresult GetCurrentProfilePath(nsAString& path) {
  nsCOMPtr<nsIProperties> dirSvc =
      do_GetService(NS_DIRECTORY_SERVICE_CONTRACTID);
  if (dirSvc) {
    nsCOMPtr<nsIFile> profD;
    // todo: is this allowed off the main thread?
    nsresult rv = dirSvc->Get(NS_APP_USER_PROFILE_50_DIR, NS_GET_IID(nsIFile),
                              getter_AddRefs(profD));
    NS_ENSURE_SUCCESS(rv, rv);
    if (profD) {
      return profD->GetPath(path);
    }
  }
  return NS_ERROR_FAILURE;
}

/// Create path directory for keystore file
nsresult GetKeyStorePath(nsAString& path) {
  nsresult rv = GetCurrentProfilePath(path);
  NS_ENSURE_SUCCESS(rv, rv);

  path.Append(NS_LITERAL_STRING_FROM_CSTRING("/keystore.db"));

  return NS_OK;
}

/// Load file contents into string
nsresult LoadFileToString(const nsCOMPtr<nsIFile>& file, nsACString& contents) {
  PRFileDesc* desc;
  nsresult rv = file->OpenNSPRFileDesc(PR_RDONLY, PR_IRUSR | PR_IWUSR, &desc);
  NS_ENSURE_SUCCESS(rv, rv);

  unsigned char buf[1024];
  int count = 0;
  while ((count = PR_Read(desc, buf, 1024)) > 0) {
    contents.Append(mozilla::Span<unsigned char>(buf, count));
  }

  if (count < 0) return mozilla::psm::GetXPCOMFromNSSError(PR_GetError());
  return NS_OK;
}

/// Open file for appending and write string to it
nsresult AppendStringToFile(const nsCOMPtr<nsIFile>& file,
                            nsACString& contents) {
  PRFileDesc* desc;
  nsresult rv = file->OpenNSPRFileDesc(PR_WRONLY | PR_CREATE_FILE | PR_APPEND,
                                       PR_IRUSR | PR_IWUSR, &desc);
  NS_ENSURE_SUCCESS(rv, rv);

  if (PR_Write(desc, contents.Data(), (int)contents.Length()) < 0) {
    return mozilla::psm::GetXPCOMFromNSSError(PR_GetError());
  }
  return NS_OK;
}

/// Import a single, encoded and encrypted key, and encoded IV as `path`
nsresult ImportKey(nsCString path, nsCString encodedKey, nsCString encodedIV) {
  // Key and IV are encoded Base64 strings
  nsCString encryptedKey, stringIV;

  nsresult rv = mozilla::Base64Decode(encodedKey, encryptedKey);
  NS_ENSURE_SUCCESS(rv, rv);

  rv = mozilla::Base64Decode(encodedIV, stringIV);
  NS_ENSURE_SUCCESS(rv, rv);

  // Key and IV need to go into SECItems to be useful
  mozilla::UniqueSECItem key = mozilla::UniqueSECItem(new SECItem());
  SECStatus stat =
      SECITEM_MakeItem(nullptr, key.get(), (unsigned char*)encryptedKey.Data(),
                       encryptedKey.Length());
  if (stat != SECSuccess) return NS_ERROR_FAILURE;

  mozilla::UniqueSECItem iv = mozilla::UniqueSECItem(new SECItem());
  stat = SECITEM_MakeItem(nullptr, iv.get(), (unsigned char*)stringIV.Data(),
                          stringIV.Length());
  if (stat != SECSuccess) return NS_ERROR_FAILURE;

  // Keystore contains one (1) "system" key which encrypts all other keys
  if (path == SYSTEM_KEY_NAME) {
    SECItem result = {siBuffer, nullptr, 0};

    // "System" key is encrypted through the SDR
    stat = PK11SDR_Decrypt(key.get(), &result, nullptr);
    if (stat != SECSuccess) return NS_ERROR_FAILURE;

    mozilla::UniquePK11SlotInfo slot(PK11_GetInternalSlot());

    SYSTEM_KEY = mozilla::UniquePK11SymKey(
        PK11_ImportSymKey(slot.get(), CKM_AES_GCM, PK11_OriginUnwrap,
                          CKA_ENCRYPT | CKA_DECRYPT, &result, nullptr));

    SECITEM_FreeItem(&result, false);
  } else {
    KEY_MAP.InsertOrUpdate(path, Key{std::move(key), std::move(iv)});
  }

  return NS_OK;
}

/// Load keys from keystore file to memory
nsresult LoadKeysFromDisk() {
  KEY_MUTEX.AssertCurrentThreadOwns();

  nsCString fileContents;

  // Get the file to the key store in the profile and turn it into a file ref
  nsAutoString filePath;
  nsresult rv = GetKeyStorePath(filePath);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIFile> file;
  rv = NS_NewLocalFile(filePath, getter_AddRefs(file));
  NS_ENSURE_SUCCESS(rv, rv);

  // Load all the file contents into one string
  rv = LoadFileToString(file, fileContents);
  if (rv == nsresult::NS_ERROR_FILE_NOT_FOUND) {
    // Non existent keystore is OK and will be handled outside of this function
    return NS_OK;
  }
  NS_ENSURE_SUCCESS(rv, rv);

  // Verify keystore file
  if (fileContents.Find(KEYSTORE_MAGIC) != 0) {
    return NS_ERROR_INVALID_SIGNATURE;
  }

  // Go through each line
  for (const auto& line : fileContents.Split('\n')) {
    int32_t delimiter1 = line.Find(":"_ns.View());
    int32_t delimiter2 = line.RFind(":"_ns.View());
    // Ignore invalid or incomplete lines
    if (delimiter1 == kNotFound || delimiter1 == delimiter2) continue;

    // Each line holds a path/identifier, a key and an IV
    nsCString path, encodedKey, encodedIV;
    path.Assign(line.Data(), delimiter1);

    encodedKey.Assign(line.Data() + delimiter1 + 1,
                      delimiter2 - delimiter1 - 1);

    encodedIV.Assign(line.Data() + delimiter2 + 1,
                     line.Length() - delimiter2 - 1);

    rv = ImportKey(path, encodedKey, encodedIV);
    NS_ENSURE_SUCCESS(rv, rv);
  }
  return NS_OK;
}

/// Create "system" key
/// `keyOut` will contain the SDR encrypted key bytes
/// `SYSTEM_KEY` will the a AES-GCM PK11SymKey created from those bytes
nsresult CreateSystemKey(Key& keyOut) {
  // Every key is 32 bytes long
  mozilla::UniqueSECItem key =
      mozilla::UniqueSECItem(SECITEM_AllocItem(nullptr, nullptr, 32));
  if (!key) return NS_ERROR_FAILURE;

  // Key data is random
  SECStatus stat = PK11_GenerateRandom(key->data, key->len);
  if (stat != SECSuccess) return NS_ERROR_FAILURE;

  mozilla::UniqueSECItem encryptedKey(nullptr);

  mozilla::UniquePK11SlotInfo slot(PK11_GetInternalSlot());

  SYSTEM_KEY = mozilla::UniquePK11SymKey(
      PK11_ImportSymKey(slot.get(), CKM_AES_GCM, PK11_OriginUnwrap,
                        CKA_ENCRYPT | CKA_DECRYPT, key.get(), nullptr));

  // Use the default SDR key
  SECItem keyid = {siBuffer, nullptr, 0};

  // PK11SDR_EncryptWithMechanism will allocate the needed buffer in SECItem
  encryptedKey.reset(new SECItem());

  stat = PK11SDR_EncryptWithMechanism(nullptr, &keyid, CKM_AES_CBC, key.get(),
                                      encryptedKey.get(), nullptr);
  if (stat != SECSuccess) return NS_ERROR_FAILURE;

  keyOut = Key{std::move(encryptedKey), mozilla::UniqueSECItem(new SECItem())};

  return NS_OK;
}

/// Create and store a new key
nsresult CreateKey(nsAutoCString& identifier, Key& keyOut) {
  // Every key is 32 bytes long
  mozilla::UniqueSECItem key =
      mozilla::UniqueSECItem(SECITEM_AllocItem(nullptr, nullptr, 32));
  if (!key) return NS_ERROR_FAILURE;

  // Key data is random
  SECStatus stat = PK11_GenerateRandom(key->data, key->len);
  if (stat != SECSuccess) return NS_ERROR_FAILURE;

  mozilla::UniqueSECItem encryptedKey(nullptr);
  // IV exists regardless of wether the key is "system"
  mozilla::UniqueSECItem iv(SECITEM_AllocItem(nullptr, nullptr, 12));

  // IV data is also random
  stat = PK11_GenerateRandom(iv->data, iv->len);
  if (stat != SECSuccess) return NS_ERROR_FAILURE;

  CK_GCM_PARAMS gcm_params;
  gcm_params.pIv = (CK_BYTE_PTR)iv->data;
  gcm_params.ulIvLen = iv->len;
  gcm_params.ulIvBits = iv->len * 8;
  gcm_params.pAAD = (CK_BYTE_PTR)identifier.get();
  gcm_params.ulAADLen = identifier.Length();
  gcm_params.ulTagBits = 128;

  SECItem gcm_item;
  gcm_item.type = siBuffer;
  gcm_item.data = (unsigned char*)&gcm_params;
  gcm_item.len = sizeof(gcm_params);

  // PK11_Encrypt needs an existing buffer
  encryptedKey.reset(SECITEM_AllocItem(nullptr, nullptr, 64));

  unsigned int encrypted_len = 0;

  stat =
      PK11_Encrypt(SYSTEM_KEY.get(), CKM_AES_GCM, &gcm_item, encryptedKey->data,
                   &encrypted_len, encryptedKey->len, key->data, key->len);
  if (stat != SECSuccess) return NS_ERROR_FAILURE;

  // Resize buffer to actual length
  stat = SECITEM_ReallocItemV2(nullptr, encryptedKey.get(), encrypted_len);
  if (stat != SECSuccess) return NS_ERROR_OUT_OF_MEMORY;

  keyOut = Key{std::move(encryptedKey), std::move(iv)};

  return NS_OK;
}

// Append key to key store file, creating it if needed
nsresult WriteKeyToDisk(nsAutoCString& identifier, Key& key) {
  // Key and IV need Base64 encoding for disk storage
  nsCString encodedKey, encodedIV;
  nsresult rv = mozilla::Base64Encode((const char*)key.key->data, key.key->len,
                                      encodedKey);
  NS_ENSURE_SUCCESS(rv, rv);

  rv = mozilla::Base64Encode((const char*)key.iv->data, key.iv->len, encodedIV);
  NS_ENSURE_SUCCESS(rv, rv);

  // Get the file to the key store in the profile and turn it into a file ref
  nsAutoString filePath;
  rv = GetKeyStorePath(filePath);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCOMPtr<nsIFile> file;
  rv = NS_NewLocalFile(filePath, getter_AddRefs(file));
  NS_ENSURE_SUCCESS(rv, rv);

  // If the file doesn't exist, we need to write the magic before anything else
  bool has_magic;
  file->Exists(&has_magic);

  nsCString fileString;
  if (!has_magic) {
    fileString.Append(KEYSTORE_MAGIC);
  }

  nsAutoCString keyEntry =
      identifier + ":"_ns + encodedKey + ":"_ns + encodedIV + "\n"_ns;
  fileString.Append(keyEntry);

  return AppendStringToFile(file, fileString);
}

/// Create "system" key
nsresult InitializeKeys() {
  nsAutoCString system(SYSTEM_KEY_NAME);

  Key key = {0, 0};

  nsresult rv = CreateSystemKey(key);
  NS_ENSURE_SUCCESS(rv, rv);

  WriteKeyToDisk(system, key);

  return NS_OK;
}

// Decrypt key with "system" key
SECStatus DecryptKey(Key& key, nsAutoCString& identifier, SECItem* data) {
  CK_GCM_PARAMS gcm_params;
  gcm_params.pIv = (CK_BYTE_PTR)key.iv->data;
  gcm_params.ulIvLen = key.iv->len;
  gcm_params.ulIvBits = key.iv->len * 8;
  gcm_params.pAAD = (CK_BYTE_PTR)identifier.get();
  gcm_params.ulAADLen = identifier.Length();
  gcm_params.ulTagBits = 128;

  SECItem gcm_item;
  gcm_item.type = siBuffer;
  gcm_item.data = (unsigned char*)&gcm_params;
  gcm_item.len = sizeof(gcm_params);

  SECITEM_AllocItem(nullptr, data, 32);

  unsigned int decrypted_len = 0;

  return PK11_Decrypt(SYSTEM_KEY.get(), CKM_AES_GCM, &gcm_item, data->data,
                      &decrypted_len, data->len, key.key->data, key.key->len);
}

/// Obtain requested key assuming owned mutex
nsresult FetchOrCreateKeyInner(nsAutoCString& identifier, SECItem* data) {
  nsresult rv;
  // Load keys if it hasn't happened yet
  if (KEY_MAP.IsEmpty()) {
    rv = LoadKeysFromDisk();
    NS_ENSURE_SUCCESS(rv, rv);
    // No keys loaded, so the keystore didn't exist before. Create it!
    if (KEY_MAP.IsEmpty()) {
      rv = InitializeKeys();
      NS_ENSURE_SUCCESS(rv, rv);
    }
  }

  // Key doesn't exist after keys have been loaded. Create it!
  if (!KEY_MAP.Contains(identifier)) {
    Key key = {};
    rv = CreateKey(identifier, key);
    NS_ENSURE_SUCCESS(rv, rv);

    rv = WriteKeyToDisk(identifier, key);
    NS_ENSURE_SUCCESS(rv, rv);

    KEY_MAP.InsertOrUpdate(identifier, std::move(key));
  }

  // Decrypt requested key with "system" key
  // Must be accessed through visitor, because UniqueSECItems can't be
  // copied and nsTHashMap doesn't return references throught Get()
  mozilla::UniqueSECItem encrypted_key;
  SECStatus stat = KEY_MAP.WithEntryHandle(
      identifier, [&identifier, &data](auto entryHandle) {
        return DecryptKey(entryHandle.Data(), identifier, data);
      });
  if (stat != SECSuccess) {
    return NS_ERROR_FAILURE;
  }
  return NS_OK;
}

nsresult FetchOrCreateKey(nsAutoCString& identifier, SECItem* data) {
  // Lock mutex here, so we can return the rv easily
  KEY_MUTEX.Lock();
  nsresult rv = FetchOrCreateKeyInner(identifier, data);
  KEY_MUTEX.Unlock();
  return rv;
}
