/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "mozilla/gtest/MozAssertions.h"
#include "mozilla/security/lockstore/lockstore_ffi_generated.h"
#include "nsString.h"
#include "nsTArray.h"
#include "nsDirectoryServiceDefs.h"
#include "nsDirectoryServiceUtils.h"
#include "nsIFile.h"

using namespace mozilla::security::lockstore;

class LockstoreParentTest : public ::testing::Test {
 protected:
  void SetUp() override {
    nsCOMPtr<nsIFile> tmpDir;
    nsresult rv =
        NS_GetSpecialDirectory(NS_OS_TEMP_DIR, getter_AddRefs(tmpDir));
    ASSERT_NS_SUCCEEDED(rv);

    nsAutoCString uuid;
    uuid.AppendPrintf("lockstore_test_%u", static_cast<unsigned>(rand()));

    rv = tmpDir->AppendNative(uuid);
    ASSERT_NS_SUCCEEDED(rv);

    rv = tmpDir->Create(nsIFile::DIRECTORY_TYPE, 0700);
    ASSERT_NS_SUCCEEDED(rv);

    rv = tmpDir->GetNativePath(mProfilePath);
    ASSERT_NS_SUCCEEDED(rv);
  }

  void TearDown() override {
    nsCOMPtr<nsIFile> tmpDir;
    if (NS_SUCCEEDED(
            NS_NewNativeLocalFile(mProfilePath, getter_AddRefs(tmpDir)))) {
      tmpDir->Remove(true);
    }
  }

  nsCString mProfilePath;
};

TEST_F(LockstoreParentTest, KeystoreOpen_ValidPath) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, KeystoreOpen_EmptyPath) {
  nsCString emptyPath;
  nsresult rv = lockstore_keystore_open(&emptyPath);
  EXPECT_EQ(rv, NS_ERROR_INVALID_ARG);
}

TEST_F(LockstoreParentTest, KeystoreCreateDek) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("test_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, KeystoreCreateDek_EmptyCollection) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString emptyCollection;
  rv = lockstore_keystore_create_dek(&emptyCollection,
                                     LockstoreSecurityLevel::LocalKey);
  EXPECT_EQ(rv, NS_ERROR_INVALID_ARG);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, KeystoreDeleteDek_Existing) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("test_delete_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  bool deleted = false;
  rv = lockstore_keystore_delete_dek(&collection, &deleted);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_TRUE(deleted);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, KeystoreDeleteDek_NonExisting) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("nonexistent_collection"_ns);
  bool deleted = true;
  rv = lockstore_keystore_delete_dek(&collection, &deleted);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_FALSE(deleted);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, KeystoreListCollections_Empty) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsTArray<nsCString> collections;
  rv = lockstore_keystore_list_collections(&collections);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_EQ(collections.Length(), 0u);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, KeystoreListCollections_Multiple) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString col1("collection1"_ns);
  nsCString col2("collection2"_ns);

  rv = lockstore_keystore_create_dek(&col1, LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_create_dek(&col2, LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  nsTArray<nsCString> collections;
  rv = lockstore_keystore_list_collections(&collections);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_EQ(collections.Length(), 2u);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, KeystoreClose_NonOpened) {
  nsresult rv = lockstore_keystore_close();
  EXPECT_EQ(rv, NS_ERROR_NOT_AVAILABLE);
}

TEST_F(LockstoreParentTest, DatastoreOpen_ValidParams) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("data_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, DatastoreOpen_NonExistentKeystore) {
  nsCString collection("data_collection"_ns);

  nsresult rv = lockstore_datastore_open(&collection);
  EXPECT_EQ(rv, NS_ERROR_NOT_AVAILABLE);
}

TEST_F(LockstoreParentTest, DatastorePutGet) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("crud_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString entryName("test_entry"_ns);
  const uint8_t testData[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  rv = lockstore_datastore_put(&collection, &entryName, testData,
                               sizeof(testData));
  EXPECT_NS_SUCCEEDED(rv);

  nsTArray<uint8_t> retrievedData;
  rv = lockstore_datastore_get(&collection, &entryName, &retrievedData);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_EQ(retrievedData.Length(), sizeof(testData));
  for (size_t i = 0; i < retrievedData.Length(); i++) {
    EXPECT_EQ(retrievedData[i], testData[i]);
  }

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, DatastoreGet_NonExistent) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("crud_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString entryName("nonexistent_entry"_ns);
  nsTArray<uint8_t> retrievedData;
  rv = lockstore_datastore_get(&collection, &entryName, &retrievedData);
  EXPECT_EQ(rv, NS_ERROR_NOT_AVAILABLE);

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, DatastoreDelete_Existing) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("delete_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString entryName("entry_to_delete"_ns);
  const uint8_t testData[] = {0xAB, 0xCD};
  rv = lockstore_datastore_put(&collection, &entryName, testData,
                               sizeof(testData));
  ASSERT_NS_SUCCEEDED(rv);

  bool deleted = false;
  rv = lockstore_datastore_delete(&collection, &entryName, &deleted);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_TRUE(deleted);

  nsTArray<uint8_t> retrievedData;
  rv = lockstore_datastore_get(&collection, &entryName, &retrievedData);
  EXPECT_EQ(rv, NS_ERROR_NOT_AVAILABLE);

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, DatastoreDelete_NonExisting) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("delete_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString entryName("nonexistent_entry"_ns);
  bool deleted = true;
  rv = lockstore_datastore_delete(&collection, &entryName, &deleted);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_FALSE(deleted);

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, DatastoreList_Empty) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("list_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  ASSERT_NS_SUCCEEDED(rv);

  nsTArray<nsCString> entries;
  rv = lockstore_datastore_list(&collection, &entries);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_EQ(entries.Length(), 0u);

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, DatastoreList_Multiple) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("list_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString entry1("entry1"_ns);
  nsCString entry2("entry2"_ns);
  nsCString entry3("entry3"_ns);
  const uint8_t data[] = {0x00};

  rv =
      lockstore_datastore_put(&collection, &entry1, data, sizeof(data));
  ASSERT_NS_SUCCEEDED(rv);

  rv =
      lockstore_datastore_put(&collection, &entry2, data, sizeof(data));
  ASSERT_NS_SUCCEEDED(rv);

  rv =
      lockstore_datastore_put(&collection, &entry3, data, sizeof(data));
  ASSERT_NS_SUCCEEDED(rv);

  nsTArray<nsCString> entries;
  rv = lockstore_datastore_list(&collection, &entries);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_EQ(entries.Length(), 3u);

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, DatastoreClose_NonExistent) {
  nsCString collection("nonexistent"_ns);
  nsresult rv = lockstore_datastore_close(&collection);
  EXPECT_EQ(rv, NS_ERROR_NOT_AVAILABLE);
}

TEST_F(LockstoreParentTest, FullWorkflow) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("workflow_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString key1("password"_ns);
  nsCString key2("token"_ns);
  const uint8_t password[] = "super_secret_password";
  const uint8_t token[] = "auth_token_12345";

  rv = lockstore_datastore_put(&collection, &key1, password,
                               sizeof(password) - 1);
  ASSERT_NS_SUCCEEDED(rv);

  rv =
      lockstore_datastore_put(&collection, &key2, token, sizeof(token) - 1);
  ASSERT_NS_SUCCEEDED(rv);

  nsTArray<nsCString> entries;
  rv = lockstore_datastore_list(&collection, &entries);
  ASSERT_NS_SUCCEEDED(rv);
  EXPECT_EQ(entries.Length(), 2u);

  nsTArray<uint8_t> retrieved;
  rv = lockstore_datastore_get(&collection, &key1, &retrieved);
  ASSERT_NS_SUCCEEDED(rv);
  EXPECT_EQ(retrieved.Length(), sizeof(password) - 1);

  const uint8_t newPassword[] = "updated_password";
  rv = lockstore_datastore_put(&collection, &key1, newPassword,
                               sizeof(newPassword) - 1);
  ASSERT_NS_SUCCEEDED(rv);

  retrieved.Clear();
  rv = lockstore_datastore_get(&collection, &key1, &retrieved);
  ASSERT_NS_SUCCEEDED(rv);
  EXPECT_EQ(retrieved.Length(), sizeof(newPassword) - 1);

  bool deleted = false;
  rv = lockstore_datastore_delete(&collection, &key2, &deleted);
  ASSERT_NS_SUCCEEDED(rv);
  EXPECT_TRUE(deleted);

  entries.Clear();
  rv = lockstore_datastore_list(&collection, &entries);
  ASSERT_NS_SUCCEEDED(rv);
  EXPECT_EQ(entries.Length(), 1u);

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  deleted = false;
  rv = lockstore_keystore_delete_dek(&collection, &deleted);
  EXPECT_NS_SUCCEEDED(rv);
  EXPECT_TRUE(deleted);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, MultipleCollections) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection1("logins"_ns);
  nsCString collection2("tokens"_ns);

  rv =
      lockstore_keystore_create_dek(&collection1, LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv =
      lockstore_keystore_create_dek(&collection2, LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection1);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection2);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString key("secret"_ns);
  const uint8_t data1[] = "login_data";
  const uint8_t data2[] = "token_data_longer";

  rv = lockstore_datastore_put(&collection1, &key, data1, sizeof(data1) - 1);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_put(&collection2, &key, data2, sizeof(data2) - 1);
  ASSERT_NS_SUCCEEDED(rv);

  nsTArray<uint8_t> retrieved1;
  rv = lockstore_datastore_get(&collection1, &key, &retrieved1);
  ASSERT_NS_SUCCEEDED(rv);
  EXPECT_EQ(retrieved1.Length(), sizeof(data1) - 1);

  nsTArray<uint8_t> retrieved2;
  rv = lockstore_datastore_get(&collection2, &key, &retrieved2);
  ASSERT_NS_SUCCEEDED(rv);
  EXPECT_EQ(retrieved2.Length(), sizeof(data2) - 1);

  EXPECT_NE(memcmp(retrieved1.Elements(), retrieved2.Elements(),
                   std::min(retrieved1.Length(), retrieved2.Length())),
            0);

  rv = lockstore_datastore_close(&collection1);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_close(&collection2);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}

TEST_F(LockstoreParentTest, LargeData) {
  nsresult rv = lockstore_keystore_open(&mProfilePath);
  ASSERT_NS_SUCCEEDED(rv);

  nsCString collection("large_data_collection"_ns);
  rv = lockstore_keystore_create_dek(&collection,
                                     LockstoreSecurityLevel::LocalKey);
  ASSERT_NS_SUCCEEDED(rv);

  rv = lockstore_datastore_open(&collection);
  ASSERT_NS_SUCCEEDED(rv);

  const size_t dataSize = 1024 * 1024;
  nsTArray<uint8_t> largeData;
  largeData.SetLength(dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    largeData[i] = static_cast<uint8_t>(i % 256);
  }

  nsCString entryName("large_entry"_ns);
  rv = lockstore_datastore_put(&collection, &entryName, largeData.Elements(),
                               largeData.Length());
  ASSERT_NS_SUCCEEDED(rv);

  nsTArray<uint8_t> retrieved;
  rv = lockstore_datastore_get(&collection, &entryName, &retrieved);
  ASSERT_NS_SUCCEEDED(rv);
  EXPECT_EQ(retrieved.Length(), dataSize);

  bool match = true;
  for (size_t i = 0; i < dataSize && match; i++) {
    match = (retrieved[i] == largeData[i]);
  }
  EXPECT_TRUE(match);

  rv = lockstore_datastore_close(&collection);
  EXPECT_NS_SUCCEEDED(rv);

  rv = lockstore_keystore_close();
  EXPECT_NS_SUCCEEDED(rv);
}
