/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const args = window.arguments;
  // args[0] is an nsISupportsString we will populate with the typed
  // phrase on accept. On cancel we leave it as the empty string.
  const out = args[0].QueryInterface(Ci.nsISupportsString);
  const input = document.getElementById("mnemonicInput");
  const dialog = document.querySelector("dialog");

  dialog.addEventListener("dialogaccept", () => {
    const phrase = (input.value || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, " ");
    out.data = phrase;
  });
  dialog.addEventListener("dialogcancel", () => {
    out.data = "";
  });
});
