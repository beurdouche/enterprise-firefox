/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <windows.h>

#include <propidl.h>
#include <propsys.h>
#include <shlobj.h>

#include "mozilla/RefPtr.h"
#include "mozilla/mscom/EnsureMTA.h"
#include "nsCOMPtr.h"

// Explorer's BitLocker property. Older SDKs omit it from propkey.h.
static const PROPERTYKEY kVolumeBitLockerProtection = {
    {0x2d15a9a1,
     0xa556,
     0x4189,
     {0x91, 0xad, 0x02, 0x74, 0x58, 0xf1, 0x1a, 0x07}},
    1717};

/**
 * Reads System.Volume.BitLockerProtection for a mount path such as "C:\".
 * Returns false if the property is missing or is not an integer.
 *
 * Runs synchronously in the process MTA because the caller's background thread
 * may not be COM-initialized.
 */
extern "C" bool felt_read_bitlocker_protection(const char16_t* aRoot,
                                               int32_t* aOutValue) {
  bool read = false;

  mozilla::mscom::EnsureMTA([&]() -> void {
    RefPtr<IPropertyStore> store;
    HRESULT hr = SHGetPropertyStoreFromParsingName(
        reinterpret_cast<const wchar_t*>(aRoot), nullptr, GPS_DEFAULT,
        IID_IPropertyStore, getter_AddRefs(store));
    if (FAILED(hr) || !store) {
      return;
    }

    PROPVARIANT value;
    PropVariantInit(&value);
    hr = store->GetValue(kVolumeBitLockerProtection, &value);
    if (SUCCEEDED(hr) && (value.vt == VT_I4 || value.vt == VT_UI4)) {
      *aOutValue = value.lVal;
      read = true;
    }
    PropVariantClear(&value);
  });

  return read;
}
