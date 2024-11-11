/**
 * @license
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import HasHsts from '../../audits/has-hsts.js';
import {networkRecordsToDevtoolsLog} from '../network-records-to-devtools-log.js';

it('marked N/A if no violations found', async () => {
  const artifacts = {
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Strict-Transport-Security', value: `max-age=63072000; includeSubDomains; preload`},
          ],
        },
      ]),
    },
  };
  const results = await HasHsts.audit(artifacts, {computedCache: new Map()});
  expect(results.details.items).toHaveLength(0);
  expect(results.notApplicable).toBeTruthy();
});

it('max-age missing, but other directives present', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Strict-Transport-Security', value: `includeSubDomains; preload`},
          ],
        },
      ]),
    },
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
  };

  const results = await HasHsts.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityHigh",
        values: undefined,
        formattedDefault: 'High'
      },
      description: {
        i18nId: "core/audits/has-hsts.js | noMaxAge",
        values: undefined,
        formattedDefault: 'No max-age directive'
      },
      directive: 'max-age',
    },
  ]);
});

it('max-age too low, but other directives present', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Strict-Transport-Security', value: `max-age=1337; includeSubDomains; preload`},
          ],
        },
      ]),
    },
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
  };

  const results = await HasHsts.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityHigh",
        values: undefined,
        formattedDefault: 'High'
      },
      description: {
        i18nId: "core/audits/has-hsts.js | lowMaxAge",
        values: undefined,
        formattedDefault: 'Max-age too low'
      },
      directive: 'max-age',
    },
  ]);
});

it('includeSubDomains missing, but other directives present', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Strict-Transport-Security', value: `max-age=63072000; preload`},
          ],
        },
      ]),
    },
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
  };

  const results = await HasHsts.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityMedium",
        values: undefined,
        formattedDefault: 'Medium'
      },
      description: {
        i18nId: "core/audits/has-hsts.js | noSubdomain",
        values: undefined,
        formattedDefault: 'No includeSubDomains directive found'
      },
      directive: 'includeSubDomains',
    },
  ]);
});

it('preload missing, but other directives present', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Strict-Transport-Security', value: `max-age=63072000; includeSubDomains`},
          ],
        },
      ]),
    },
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
  };

  const results = await HasHsts.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityMedium",
        values: undefined,
        formattedDefault: 'Medium'
      },
      description: {
        i18nId: "core/audits/has-hsts.js | noPreload",
        values: undefined,
        formattedDefault: 'No preload directive found'
      },
      directive: 'preload',
    },
  ]);
});

it('No HSTS header found', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Foo-Header', value: `max-age=63072000; includeSubDomains; preload`},
          ],
        },
      ]),
    },
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
  };

  const results = await HasHsts.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityHigh",
        values: undefined,
        formattedDefault: 'High'
      },
      description: {
        i18nId: "core/audits/has-hsts.js | noHsts",
        values: undefined,
        formattedDefault: 'No HSTS header found'
      },
      directive: undefined,
    },
  ]);
});

it('Messed up directive, but other actual HSTS directives present.', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Strict-Transport-Security', value: `max-age=63072000; fooDirective; includeSubDomains; preload`},
          ],
        },
      ]),
    },
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
  };

  const results = await HasHsts.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityLow",
        values: undefined,
        formattedDefault: 'Low'
      },
      description: {
        i18nId: "core/audits/has-hsts.js | invalidSyntax",
        values: undefined,
        formattedDefault: 'Invalid syntax'
      },
      directive: "foodirective",
    },
  ]);
});

it('Messed up directive and one more directive missing.', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Strict-Transport-Security', value: `max-age=63072000; fooDirective; preload`},
          ],
        },
      ]),
    },
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
  };

  const results = await HasHsts.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityMedium",
        values: undefined,
        formattedDefault: 'Medium'
      },
      description: {
        i18nId: "core/audits/has-hsts.js | noSubdomain",
        values: undefined,
        formattedDefault: 'No includeSubDomains directive found'
      },
      directive: "includeSubDomains",
    },
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityLow",
        values: undefined,
        formattedDefault: 'Low'
      },
      description: {
        i18nId: "core/audits/has-hsts.js | invalidSyntax",
        values: undefined,
        formattedDefault: 'Invalid syntax'
      },
      directive: "foodirective",
    },
  ]);
});

describe('getRawHsts', () => {
  it('basic case', async () => {
    const artifacts = {
      URL: {
        requestedUrl: 'https://example.com',
        mainDocumentUrl: 'https://example.com',
        finalDisplayedUrl: 'https://example.com',
      },
      devtoolsLogs: {
        defaultPass: networkRecordsToDevtoolsLog([
          {
            url: 'https://example.com',
            responseHeaders: [
              {
                name: 'Strict-Transport-Security',
                value: `max-age=63072000; includeSubDomains; preload`,
              },
            ],
          },
        ]),
      },
    };
    const {hstsHeaders} =
      await HasHsts.getRawHsts(artifacts, {computedCache: new Map()});
    expect(hstsHeaders).toEqual([
      `max-age=63072000`,
      `includesubdomains`,
      `preload`,
    ]);
  });

  it('ignore if empty', async () => {
    const artifacts = {
      URL: {
        requestedUrl: 'https://example.com',
        mainDocumentUrl: 'https://example.com',
        finalDisplayedUrl: 'https://example.com',
      },
      devtoolsLogs: {
        defaultPass: networkRecordsToDevtoolsLog([
          {
            url: 'https://example.com',
            responseHeaders: [
              {
                name: 'Strict-Transport-Security',
                value: ``,
              },
            ],
          },
        ]),
      },
    };
    const {hstsHeaders} =
      await HasHsts.getRawHsts(artifacts, {computedCache: new Map()});
    expect(hstsHeaders).toEqual([
      ``,
    ]);
  });

  it('ignore if only whitespace', async () => {
    const artifacts = {
      URL: {
        requestedUrl: 'https://example.com',
        mainDocumentUrl: 'https://example.com',
        finalDisplayedUrl: 'https://example.com',
      },
      devtoolsLogs: {
        defaultPass: networkRecordsToDevtoolsLog([
          {
            url: 'https://example.com',
            responseHeaders: [
              {
                name: 'Strict-Transport-Security',
                value: '   \t',
              },
            ],
          },
        ]),
      },
    };
    const {hstsHeaders} =
      await HasHsts.getRawHsts(artifacts, {computedCache: new Map()});
    expect(hstsHeaders).toEqual([
      ``,
    ]);
  });
});

describe('constructResults', () => {
  it('passes with no findings', () => {
    const {score, results} = HasHsts.constructResults([ 'max-age=31536000', 'includesubdomains', 'preload' ]);
    expect(score).toEqual(1);
    expect(results).toEqual([]);
  });

  it('constructs result based on misconfigured HSTS header', () => {
    const {score, results} = HasHsts.constructResults([ 'max-age=31536000', 'foo-directive', 'includesubdomains', 'preload' ]);
    expect(score).toEqual(1);
    expect(results).toMatchObject([
      {
        description: {
          formattedDefault: 'Invalid syntax',
          i18nId: 'core/audits/has-hsts.js | invalidSyntax',
          values: undefined,
        },
        directive: 'foo-directive',
        severity: {
          formattedDefault: 'Low',
          i18nId: 'core/lib/i18n/i18n.js | itemSeverityLow',
          values: undefined,
        },
      },
    ]);
  });

  it('returns single item for no HSTS', () => {
    const {score, results} = HasHsts.constructResults([]);
    expect(score).toEqual(0);
    expect(results).toMatchObject([
      {
        description: {
          formattedDefault: 'No HSTS header found',
          i18nId: 'core/audits/has-hsts.js | noHsts',
          values: undefined,
        },
        directive: undefined,
        severity: {
          formattedDefault: 'High',
          i18nId: 'core/lib/i18n/i18n.js | itemSeverityHigh',
          values: undefined,
        },

      },
    ]);
  });
});
