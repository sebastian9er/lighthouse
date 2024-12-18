/**
 * @license
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import ClickjackingMitigation from '../../audits/clickjacking-mitigation.js';
import {networkRecordsToDevtoolsLog} from '../network-records-to-devtools-log.js';

it('marked N/A if no violations found', async () => {
  const artifacts = {
    URL: {
      requestedUrl: 'https://example.com',
      mainDocumentUrl: 'https://example.com',
      finalDisplayedUrl: 'https://example.com',
    },
    MetaElements: [],
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'X-Frame-Options', value: `SAMEORIGIN`},
            {
              name: 'Content-Security-Policy',
              value:
                  `script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; report-uri https://csp.example.com`
            },
          ],
        },
      ]),
    },
  };
  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.details.items).toHaveLength(0);
  expect(results.notApplicable).toBeTruthy();
});

it('No XFO header but CSP header found', async () => {
  const artifacts = {
    MetaElements: [],
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
                        {
              name: 'Content-Security-Policy',
              value:
                  `script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; report-uri https://csp.example.com`
            },
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

  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.details.items).toHaveLength(0);
  expect(results.notApplicable).toBeTruthy();
});

it('No CSP header but XFO header found', async () => {
  const artifacts = {
    MetaElements: [],
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
                        {
              name: 'X-Frame-Options',
              value:
                  `SAMEORIGIN`
            },
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

  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.details.items).toHaveLength(0);
  expect(results.notApplicable).toBeTruthy();
});

it('No CSP and no XFO headers but foo header found', async () => {
  const artifacts = {
    MetaElements: [],
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

  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('High');
  expect(results.details.items[0].description)
      .toBeDisplayString('No Clickjacking mitigation found.');
  expect(results.details.items).toMatchObject([
    {
      directive: undefined,
    },
  ]);
});

it('No CSP and no XFO headers and not Meta but foo header found', async () => {
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

  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('High');
  expect(results.details.items[0].description)
      .toBeDisplayString('No Clickjacking mitigation found.');
  expect(results.details.items).toMatchObject([
    {
      directive: undefined,
    },
  ]);
});

it('Messed up XFO directive and no CSP present.', async () => {
  const artifacts = {
    MetaElements: [],
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'X-Frame-Options', value: `fooDirective`},
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

  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('High');
  expect(results.details.items[0].description)
      .toBeDisplayString('No Clickjacking mitigation found.');
  expect(results.details.items).toMatchObject([
    {
      directive: undefined,
    },
  ]);
});

it('Messed up CSP directive and no XFO present.', async () => {
  const artifacts = {
    MetaElements: [],
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'Content-Security-Policy', value: `foo-directive 'none'; report-uri https://csp.example.com`},
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

  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('High');
  expect(results.details.items[0].description)
      .toBeDisplayString('No Clickjacking mitigation found.');
  expect(results.details.items).toMatchObject([
    {
      directive: undefined,
    },
  ]);
});

it('Messed up CSP and XFO directives.', async () => {
  const artifacts = {
    MetaElements: [],
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
            {name: 'X-Frame-Options', value: `fooDirective`},
            {name: 'Content-Security-Policy', value: `foo-directive 'none'; report-uri https://csp.example.com`},
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

  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.notApplicable).toBeFalsy();
  expect(results.details.items[0].severity).toBeDisplayString('High');
  expect(results.details.items[0].description)
      .toBeDisplayString('No Clickjacking mitigation found.');
  expect(results.details.items).toMatchObject([
    {
      directive: undefined,
    },
  ]);
});

it('Frame-ancestors in the MetaElement and no XFO present.', async () => {
  const artifacts = {
    MetaElements: [
      {
        httpEquiv: 'Content-Security-Policy',
        content: `frame-ancestors 'none'`,
      },
    ],
    devtoolsLogs: {
      defaultPass: networkRecordsToDevtoolsLog([
        {
          url: 'https://example.com',
          responseHeaders: [
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

  const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.details.items).toHaveLength(0);
  expect(results.notApplicable).toBeTruthy();
});

it('Messed up CSP directive in the header, but frame-ancestors in the MetaElement and no XFO present.',
   async () => {
     const artifacts = {
       MetaElements: [
         {
           httpEquiv: 'Content-Security-Policy',
           content: `frame-ancestors 'self'`,
         },
       ],
       devtoolsLogs: {
         defaultPass: networkRecordsToDevtoolsLog([
           {
             url: 'https://example.com',
             responseHeaders: [
               {
                 name: 'Content-Security-Policy',
                 value:
                     `foo-directive 'none'; report-uri https://csp.example.com`
               },
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

       const results =
      await ClickjackingMitigation.audit(artifacts, {computedCache: new Map()});
  expect(results.details.items).toHaveLength(0);
  expect(results.notApplicable).toBeTruthy();
   });

describe('getRawCspsAndXfo', () => {
  it('basic case', async () => {
    const artifacts = {
      MetaElements: [
        {
          httpEquiv: 'Content-Security-Policy',
          content: `default-src 'none'`,
        },
      ],
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
                name: 'X-Frame-Options',
                value: `SAMEORIGIN`,
              },
              {
                name: 'Content-Security-Policy',
                value: `frame-ancestors 'self'`,
              },
            ],
          },
        ]),
      },
    };
    const {cspHeadersAndMetaTags, xfoHeaders} =
      await ClickjackingMitigation.getRawCspsAndXfo(artifacts, {computedCache: new Map()});
    expect(cspHeadersAndMetaTags).toEqual(`frame-ancestors'self';default-src'none'`);
    expect(xfoHeaders).toEqual([`sameorigin`]);
  });

  it('ignore if empty', async () => {
    const artifacts = {
      MetaElements: [],
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
                name: 'Content-Security-Policy',
                value: ``,
              },
              {
                name: 'X-Frame-Options',
                value: `deny`,
              },
            ],
          },
        ]),
      },
    };
    const {cspHeadersAndMetaTags, xfoHeaders} =
      await ClickjackingMitigation.getRawCspsAndXfo(artifacts, {computedCache: new Map()});
    expect(cspHeadersAndMetaTags).toEqual(``);
    expect(xfoHeaders).toEqual([
      `deny`,
    ]);
  });

  it('ignore if only whitespace', async () => {
    const artifacts = {
      MetaElements: [],
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
                name: 'Content-Security-Policy',
                value: '   \t',
              },
              {
                name: 'X-Frame-Options',
                value: 'DENY',
              },
            ],
          },
        ]),
      },
    };
    const {cspHeadersAndMetaTags, xfoHeaders} =
      await ClickjackingMitigation.getRawCspsAndXfo(artifacts, {computedCache: new Map()});
    expect(cspHeadersAndMetaTags).toEqual(``);
    expect(xfoHeaders).toEqual([
      `deny`,
    ]);
  });
});

describe('constructResults', () => {
  it('passes with no findings', () => {
    const {score, results} =
        ClickjackingMitigation.constructResults(``, [`deny`]);
    expect(score).toEqual(1);
    expect(results).toEqual([]);
  });

  it('constructs result based on misconfigured XFO header', () => {
    const {score, results} =
        ClickjackingMitigation.constructResults(``, ['foo-directive']);
    expect(score).toEqual(0);
    expect(results[0].severity).toBeDisplayString('High');
    expect(results[0].description)
        .toBeDisplayString(
            'No Clickjacking mitigation found.');
    expect(results).toMatchObject([
      {
        directive: undefined,
      },
    ]);
  });

  it('returns single item for no XFO and no CSP', () => {
    const {score, results} = ClickjackingMitigation.constructResults(``, []);
    expect(score).toEqual(0);
    expect(results[0].severity).toBeDisplayString('High');
    expect(results[0].description)
        .toBeDisplayString('No Clickjacking mitigation found.');
    expect(results).toMatchObject([
      {
        directive: undefined,
      },
    ]);
  });
});
