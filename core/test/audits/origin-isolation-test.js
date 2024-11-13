/**
 * @license
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import OriginIsolation from '../../audits/origin-isolation.js';
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
            {name: 'Cross-Origin-Opener-Policy', value: `same-origin`},
          ],
        },
      ]),
    },
  };
  const results = await OriginIsolation.audit(artifacts, {computedCache: new Map()});
  expect(results.details.items).toHaveLength(0);
  expect(results.notApplicable).toBeTruthy();
});

it('No COOP header found', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Foo-Header', value: `same-origin`},
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

  const results = await OriginIsolation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityHigh",
        values: undefined,
        formattedDefault: 'High'
      },
      description: {
        i18nId: "core/audits/origin-isolation.js | noCoop",
        values: undefined,
        formattedDefault: 'No COOP header found'
      },
      directive: undefined,
    },
  ]);
});

it('Messed up directive.', async () => {
  const artifacts = {
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Cross-Origin-Opener-Policy', value: `fooDirective`},
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

  const results = await OriginIsolation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items).toMatchObject([
    {
      severity: {
        i18nId: "core/lib/i18n/i18n.js | itemSeverityLow",
        values: undefined,
        formattedDefault: 'Low'
      },
      description: {
        i18nId: "core/audits/origin-isolation.js | invalidSyntax",
        values: undefined,
        formattedDefault: 'Invalid syntax'
      },
      directive: "foodirective",
    },
  ]);
});

describe('getRawCoop', () => {
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
                name: 'Cross-Origin-Opener-Policy',
                value: `same-origin`,
              },
            ],
          },
        ]),
      },
    };
    const {coopHeaders} =
      await OriginIsolation.getRawCoop(artifacts, {computedCache: new Map()});
    expect(coopHeaders).toEqual([
      `same-origin`,
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
                name: 'Cross-Origin-Opener-Policy',
                value: ``,
              },
            ],
          },
        ]),
      },
    };
    const {coopHeaders} =
      await OriginIsolation.getRawCoop(artifacts, {computedCache: new Map()});
    expect(coopHeaders).toEqual([
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
                name: 'Cross-Origin-Opener-Policy',
                value: '   \t',
              },
            ],
          },
        ]),
      },
    };
    const {coopHeaders} =
      await OriginIsolation.getRawCoop(artifacts, {computedCache: new Map()});
    expect(coopHeaders).toEqual([
      ``,
    ]);
  });
});

describe('constructResults', () => {
  it('passes with no findings', () => {
    const {score, results} = OriginIsolation.constructResults([ 'same-origin' ]);
    expect(score).toEqual(1);
    expect(results).toEqual([]);
  });

  it('constructs result based on misconfigured COOP header', () => {
    const {score, results} = OriginIsolation.constructResults([ 'foo-directive' ]);
    expect(score).toEqual(1);
    expect(results).toMatchObject([
      {
        description: {
          formattedDefault: 'Invalid syntax',
          i18nId: 'core/audits/origin-isolation.js | invalidSyntax',
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

  it('returns single item for no COOP', () => {
    const {score, results} = OriginIsolation.constructResults([]);
    expect(score).toEqual(0);
    expect(results).toMatchObject([
      {
        description: {
          formattedDefault: 'No COOP header found',
          i18nId: 'core/audits/origin-isolation.js | noCoop',
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
