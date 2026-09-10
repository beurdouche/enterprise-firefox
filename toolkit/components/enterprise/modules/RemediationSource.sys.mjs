/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Where a signed remediation document comes from. A source only fetches bytes:
 * it does not parse the manifest and cannot produce something the executor will
 * accept. Everything it returns has to survive RemediationVerifier.verify().
 */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  createEnterpriseLogger:
    "resource://gre/modules/enterprise/EnterpriseCommon.sys.mjs",
});

ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return lazy.createEnterpriseLogger("RemediationSource");
});

/**
 * Reads a document from a directory holding, for each tool id,
 * `<id>.manifest.json`, `<id>.sig` and `<id>.chain.pem`.
 *
 * This is how the feature is demonstrated before the console can serve
 * documents. It is not a shortcut: what it returns goes through exactly the
 * same verification as anything fetched over the network.
 */
export class LocalFileSource {
  /**
   * @param {string} directory Absolute path holding the document files.
   */
  constructor(directory) {
    this.directory = directory;
  }

  /**
   * @param {string} toolId
   * @returns {Promise<import("./RemediationVerifier.sys.mjs").SignedRemediation>}
   */
  async fetch(toolId) {
    const read = async suffix =>
      IOUtils.readUTF8(PathUtils.join(this.directory, `${toolId}${suffix}`));

    const [manifestText, signature, certChain] = await Promise.all([
      read(".manifest.json"),
      read(".sig"),
      read(".chain.pem"),
    ]);

    lazy.log.debug(`Read local remediation document for ${toolId}`);
    return {
      manifestText,
      signature: signature.trim(),
      certChain,
      origin: "local-file",
    };
  }
}

/**
 * Fetches a document from the enterprise console.
 *
 * Deliberately unimplemented: the console does not serve these yet, and a stub
 * that returned anything would be a second path into the executor. Landing it
 * is a matter of filling in three fetches; the verification it feeds is already
 * written and tested.
 */
export class ConsoleSource {
  async fetch() {
    throw new Error("ConsoleSource is not implemented yet");
  }
}
