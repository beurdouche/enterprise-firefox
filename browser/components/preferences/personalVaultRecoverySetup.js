/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const args = window.arguments;
  // args[0] is the mnemonic (nsISupportsString) passed in from the caller.
  // args[1] is an nsISupportsPRBool that we set to true on accept.
  const mnemonicString = args[0].QueryInterface(Ci.nsISupportsString).data;
  const result = args[1].QueryInterface(Ci.nsISupportsPRBool);
  const words = mnemonicString.split(/\s+/).filter(w => w.length > 0);

  const grid = document.getElementById("mnemonicGrid");
  words.forEach((word, idx) => {
    const cell = document.createElement("div");
    cell.textContent = `${idx + 1}. ${word}`;
    grid.appendChild(cell);
  });

  const dialog = document.querySelector("dialog");
  const checkbox = document.getElementById("confirmSaved");
  const acceptButton = dialog.getButton("accept");
  acceptButton.disabled = true;
  checkbox.addEventListener("change", () => {
    acceptButton.disabled = !checkbox.checked;
  });

  dialog.addEventListener("dialogaccept", () => {
    result.data = true;
  });
  dialog.addEventListener("dialogcancel", () => {
    result.data = false;
  });
});
