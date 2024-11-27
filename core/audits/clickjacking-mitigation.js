/**
 * @license
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Audit} from './audit.js';
import {MainResource} from '../computed/main-resource.js';
import * as i18n from '../lib/i18n/i18n.js';

const UIStrings = {
  /** Title of a Lighthouse audit that evaluates whether the set CSP or XFO header is mitigating Clickjacking attacks. "XFO" stands for "X-Frame-Options". "CSP" stands for "Content-Security-Policy". */
  title: 'Use XFO or CSP to mitigate Clickjacking attacks.',
  /** Description of a Lighthouse audit that evaluates whether the set CSP or XFO header is mitigating Clickjacking attacks. This is displayed after a user expands the section to see more. No character length limits. The last sentence starting with 'Learn' becomes link text to additional documentation. "XFO" stands for "X-Frame-Options". "CSP" stands for "Content-Security-Policy". */
  description: 'Deployment of either the X-Frame-Options or Content-Security-Policy (with the frame-ancestors directive) header will prevent Clickjacking attacks. While the XFO header is simpler to deploy, the CSP header is more flexible. [Learn more about Clickjacking prevention](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Clickjacking).',
  /** Summary text for the results of a Lighthouse audit that evaluates whether the set CSP or XFO header is mitigating Clickjacking attacks. This is displayed if there is neither a CSP nor XFO header deployed. "XFO" stands for "X-Frame-Options". "CSP" stands for "Content-Security-Policy". */
  noClickjackingMitigation: 'No Clickjacking mitigation found.',
  /** Summary text for the results of a Lighthouse audit that evaluates whether the set CSP or XFO header is mitigating Clickjacking attacks. This is displayed if the "frame-ancestors" directive is found, but the "self" and "none" keyword is missing. "XFO" stands for "X-Frame-Options". "CSP" stands for "Content-Security-Policy". */
  frameAncestorsNoSelfNoNone: 'The frame-ancestors directive was found, but self and none are missing. The developer needs to make sure it is configured correctly to mitigate Clickjacking attacks.',
  /** Summary text for the results of a Lighthouse audit that evaluates whether the set CSP or XFO header is mitigating Clickjacking attacks. This is displayed the XFO header is present, but the "SAMEORIGIN" and "DENY" keywords are missing. "XFO" stands for "X-Frame-Options". "CSP" stands for "Content-Security-Policy". */
  xfoNoSelfNoNone: 'The X-Frame-Options header was found, but neither SAMEORIGIN nor DENY was present.',
  /** Summary text for the results of a Lighthouse audit that evaluates whether the set CSP or XFO header is mitigating Clickjacking attacks. This is displayed if a CSP header is present, but no "frame-ancestors" directive within and no XFO header at all. "XFO" stands for "X-Frame-Options". "CSP" stands for "Content-Security-Policy". */
  headersPresentNoClickjackingMitigation: 'No Clickjacking mitigation is present, even though a CSP header is.',
  /** Label for a column in a data table; entries will be a directive of the XFO or CSP header. "XFO" stands for "X-Frame-Options". "CSP" stands for "Content-Security-Policy". */
  columnDirective: 'Directive',
  /** Label for a column in a data table; entries will be the severity of an issue with the XFO or CSP header. "XFO" stands for "X-Frame-Options". "CSP" stands for "Content-Security-Policy". */
  columnSeverity: 'Severity',
};

const str_ = i18n.createIcuMessageFn(import.meta.url, UIStrings);

class ClickjackingMitigation extends Audit {
  /**
   * @return {LH.Audit.Meta}
   */
  static get meta() {
    return {
      id: 'clickjacking-mitigation',
      scoreDisplayMode: Audit.SCORING_MODES.INFORMATIVE,
      title: str_(UIStrings.title),
      description: str_(UIStrings.description),
      requiredArtifacts: ['devtoolsLogs', 'MetaElements', 'URL'],
    };
  }


  /**
   * @param {LH.Artifacts} artifacts
   * @param {LH.Audit.Context} context
   * @return {Promise<{cspHeadersAndMetaTags: string, xfoHeaders: string[]}>}
   */
  static async getRawCspsAndXfo(artifacts, context) {
    const devtoolsLog = artifacts.devtoolsLogs[Audit.DEFAULT_PASS];
    const mainResource =
        await MainResource.request({devtoolsLog, URL: artifacts.URL}, context);

    const cspMetaTags =
        artifacts.MetaElements
            .filter(m => {
              return m.httpEquiv &&
                  m.httpEquiv.toLowerCase() === 'content-security-policy';
            })
            .flatMap(m => (m.content || '').split(','));
    const cspHeaders =
        mainResource.responseHeaders
            .filter(h => {
              return h.name.toLowerCase() === 'content-security-policy';
            })
            .flatMap(h => h.value.split(','));
    let xfoHeaders = mainResource.responseHeaders
                         .filter(h => {
                           return h.name.toLowerCase() === 'x-frame-options';
                         })
                         .flatMap(h => h.value);

    const cspHeadersAndMetaTags =
        cspHeaders.map(v => v.toLowerCase())
            .concat(cspMetaTags.map(v => v.toLowerCase()))
            .join(';').replace(/\s/g, '');

    // Sanitize the XFO header value.
    xfoHeaders = xfoHeaders.map(v => v.toLowerCase().replace(/\s/g, ''));

    return {cspHeadersAndMetaTags, xfoHeaders};
  }

  /**
   * @param {string | undefined} directive
   * @param {LH.IcuMessage | string} findingDescription
   * @param {LH.IcuMessage=} severity
   * @return {LH.Audit.Details.TableItem}
   */
  static findingToTableItem(directive, findingDescription, severity) {
    return {
      directive: directive,
      description: findingDescription,
      severity,
    };
  }

  /**
   * @param {string} cspHeadersAndMetaTags
   * @param {string[]} xfoHeaders
   * @return {{score: number, results: LH.Audit.Details.TableItem[]}}
   */
  static constructResults(cspHeadersAndMetaTags, xfoHeaders) {
    const rawXfo = [...xfoHeaders];
    const allowedDirectives = ['deny', 'sameorigin'];
    const violations = [];
    const warnings = [];
    let frameAncestorsPresent = false;

    // If there is none of the two headers, return early.
    if (!rawXfo.length && !cspHeadersAndMetaTags.length) {
      return {
        score: 0,
        results: [{
          severity: str_(i18n.UIStrings.itemSeverityHigh),
          description: str_(UIStrings.noClickjackingMitigation),
          directive: undefined,
        }],
      };
    }

    // Check for frame-ancestors in CSP.
    if (cspHeadersAndMetaTags.length) {
      for (const cspDirective of cspHeadersAndMetaTags.split(';')) {
        if (cspDirective.includes('frame-ancestors')) {
          frameAncestorsPresent = true;
        }
        // If frame-ancestors but not self and not none, warn the developer.
        if (cspDirective.includes('frame-ancestors') &&
            !(cspDirective.includes('self') || cspDirective.includes('none'))) {
          warnings.push({
            severity: str_(i18n.UIStrings.itemSeverityMedium),
            description: str_(UIStrings.frameAncestorsNoSelfNoNone),
            directive: cspDirective,
          });
        }
      }
    }

    for (const actualDirective of xfoHeaders) {
      // If there is a directive that's not sameorigin or deny.
      if (!allowedDirectives.includes(actualDirective)) {
        violations.push({
          severity: str_(i18n.UIStrings.itemSeverityHigh),
          description: str_(UIStrings.xfoNoSelfNoNone),
          directive: actualDirective,
        });
      }
    }

    // The CSP header is present, but has no frame-ancestors. XFO is missing.
    if (!frameAncestorsPresent && !rawXfo.length) {
      violations.push({
        severity: str_(i18n.UIStrings.itemSeverityHigh),
        description: str_(UIStrings.headersPresentNoClickjackingMitigation),
        directive: undefined,
      });
    }

    const results = [
      ...violations.map(
          f => this.findingToTableItem(
              f.directive, f.description,
              str_(i18n.UIStrings.itemSeverityHigh))),
      ...warnings.map(
          f => this.findingToTableItem(
              f.directive, f.description,
              str_(i18n.UIStrings.itemSeverityMedium))),
    ];

    return {score: violations.length || warnings.length ? 0 : 1, results};
  }

  /**
   * @param {LH.Artifacts} artifacts
   * @param {LH.Audit.Context} context
   * @return {Promise<LH.Audit.Product>}
   */
  static async audit(artifacts, context) {
    const {cspHeadersAndMetaTags, xfoHeaders} = await this.getRawCspsAndXfo(artifacts, context);
    const {score, results} = this.constructResults(cspHeadersAndMetaTags, xfoHeaders);

    /** @type {LH.Audit.Details.Table['headings']} */
    const headings = [
      /* eslint-disable max-len */
      {key: 'description', valueType: 'text', subItemsHeading: {key: 'description'}, label: str_(i18n.UIStrings.columnDescription)},
      {key: 'directive', valueType: 'code', subItemsHeading: {key: 'directive'}, label: str_(UIStrings.columnDirective)},
      {key: 'severity', valueType: 'text', subItemsHeading: {key: 'severity'}, label: str_(UIStrings.columnSeverity)},
      /* eslint-enable max-len */
    ];
    const details = Audit.makeTableDetails(headings, results);

    return {
      score,
      notApplicable: !results.length,
      details,
    };
  }
}

export default ClickjackingMitigation;
export {UIStrings};
