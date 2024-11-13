/**
 * @license
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @type {Smokehouse.ExpectedRunnerResult}
 * Expected Lighthouse results a site with HSTS header issues.
 */
const expectations = {
  lhr: {
    requestedUrl: 'https://developer.mozilla.org/en-US/',
    finalDisplayedUrl: 'https://developer.mozilla.org/en-US/',
    audits: {
      'has-hsts': {
        score: 1,
      },
    },
  },
};

export default {
  id: 'hsts-missing-directives',
  expectations,
};
