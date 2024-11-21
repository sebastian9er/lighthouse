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
<<<<<<< HEAD
<<<<<<< HEAD
  const results =
      await OriginIsolation.audit(artifacts, {computedCache: new Map()});
=======
  const results = await OriginIsolation.audit(artifacts, {computedCache: new Map()});
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
  const results =
      await OriginIsolation.audit(artifacts, {computedCache: new Map()});
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
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

<<<<<<< HEAD
<<<<<<< HEAD
  const results =
      await OriginIsolation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('High');
  expect(results.details.items[0].description)
      .toBeDisplayString('No COOP header found');
  expect(results.details.items).toMatchObject([
    {
=======
  const results = await OriginIsolation.audit(artifacts, {computedCache: new Map()});
=======
  const results =
      await OriginIsolation.audit(artifacts, {computedCache: new Map()});
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('High');
  expect(results.details.items[0].description)
      .toBeDisplayString('No COOP header found');
  expect(results.details.items).toMatchObject([
    {
<<<<<<< HEAD
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
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
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

<<<<<<< HEAD
<<<<<<< HEAD
  const results =
      await OriginIsolation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('Low');
  expect(results.details.items[0].description)
      .toBeDisplayString('Invalid syntax');
  expect(results.details.items).toMatchObject([
    {
      directive: 'foodirective',
=======
  const results = await OriginIsolation.audit(artifacts, {computedCache: new Map()});
=======
  const results =
      await OriginIsolation.audit(artifacts, {computedCache: new Map()});
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('Low');
  expect(results.details.items[0].description)
      .toBeDisplayString('Invalid syntax');
  expect(results.details.items).toMatchObject([
    {
<<<<<<< HEAD
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
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
      directive: 'foodirective',
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
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
<<<<<<< HEAD
<<<<<<< HEAD
    const coopHeaders =
=======
    const {coopHeaders} =
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
    const coopHeaders =
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
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
<<<<<<< HEAD
<<<<<<< HEAD
    const coopHeaders =
=======
    const {coopHeaders} =
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
    const coopHeaders =
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
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
<<<<<<< HEAD
<<<<<<< HEAD
    const coopHeaders =
=======
    const {coopHeaders} =
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
    const coopHeaders =
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
      await OriginIsolation.getRawCoop(artifacts, {computedCache: new Map()});
    expect(coopHeaders).toEqual([
      ``,
    ]);
  });
});

describe('constructResults', () => {
  it('passes with no findings', () => {
<<<<<<< HEAD
<<<<<<< HEAD
    const {score, results} = OriginIsolation.constructResults(['same-origin']);
=======
    const {score, results} = OriginIsolation.constructResults([ 'same-origin' ]);
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
    const {score, results} = OriginIsolation.constructResults(['same-origin']);
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
    expect(score).toEqual(1);
    expect(results).toEqual([]);
  });

  it('constructs result based on misconfigured COOP header', () => {
<<<<<<< HEAD
<<<<<<< HEAD
    const {score, results} =
        OriginIsolation.constructResults(['foo-directive']);
    expect(score).toEqual(1);
    expect(results[0].severity).toBeDisplayString('Low');
    expect(results[0].description)
        .toBeDisplayString('Invalid syntax');
    expect(results).toMatchObject([
      {
        directive: 'foo-directive',
=======
    const {score, results} = OriginIsolation.constructResults([ 'foo-directive' ]);
=======
    const {score, results} =
        OriginIsolation.constructResults(['foo-directive']);
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
    expect(score).toEqual(1);
    expect(results[0].severity).toBeDisplayString('Low');
    expect(results[0].description)
        .toBeDisplayString('Invalid syntax');
    expect(results).toMatchObject([
      {
        directive: 'foo-directive',
<<<<<<< HEAD
        severity: {
          formattedDefault: 'Low',
          i18nId: 'core/lib/i18n/i18n.js | itemSeverityLow',
          values: undefined,
        },
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
      },
    ]);
  });

  it('returns single item for no COOP', () => {
    const {score, results} = OriginIsolation.constructResults([]);
    expect(score).toEqual(0);
<<<<<<< HEAD
<<<<<<< HEAD
    expect(results[0].severity).toBeDisplayString('High');
    expect(results[0].description)
        .toBeDisplayString('No COOP header found');
    expect(results).toMatchObject([
      {
        directive: undefined,
=======
=======
    expect(results[0].severity).toBeDisplayString('High');
    expect(results[0].description)
        .toBeDisplayString('No COOP header found');
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
    expect(results).toMatchObject([
      {
        directive: undefined,
<<<<<<< HEAD
        severity: {
          formattedDefault: 'High',
          i18nId: 'core/lib/i18n/i18n.js | itemSeverityHigh',
          values: undefined,
        },

>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
      },
    ]);
  });
});
