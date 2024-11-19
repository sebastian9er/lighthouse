/**
 * @license
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @type {Smokehouse.ExpectedRunnerResult}
 * Expected Lighthouse results for a site with a missing COOP header.
 */
const expectations = {
  lhr: {
    requestedUrl: 'https://example.com/',
    finalDisplayedUrl: 'https://example.com/',
    audits: {
      'origin-isolation': {
        score: 1,
      },
    },
  },
};

export default {
  id: 'origin-isolation-coop-header-missing',
  expectations,
};
