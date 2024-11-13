/**
 * @license
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
import {MainResource} from '../computed/main-resource.js';
import * as i18n from '../lib/i18n/i18n.js';

import {Audit} from './audit.js';

=======
=======
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
import {Audit} from './audit.js';
import {MainResource} from '../computed/main-resource.js';
import * as i18n from '../lib/i18n/i18n.js';

<<<<<<< HEAD
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
import {MainResource} from '../computed/main-resource.js';
import * as i18n from '../lib/i18n/i18n.js';

import {Audit} from './audit.js';

>>>>>>> 4d7aa600b (Re-format origin isolation audit and enable it in the default config.)
=======
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
const UIStrings = {
  /** Title of a Lighthouse audit that evaluates the security of a page's COOP header for origin isolation. "COOP" stands for "Cross-Origin-Opener-Policy". */
  title: 'Ensure the proper usage of the COOP header to isolate the origin.',
  /** Description of a Lighthouse audit that evaluates the security of a page's COOP header for origin isolation. This is displayed after a user expands the section to see more. No character length limits. The last sentence starting with 'Learn' becomes link text to additional documentation. "COOP" stands for "Cross-Origin-Opener-Policy". */
  description: 'Deployment of the COOP header allows isolation of the top-level document to not share a browsing context group with cross-origin documents. ' +
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    '[Learn what the COOP header is and how it should be deployed.](https://web.dev/articles/why-coop-coep#coop)',
=======
    '[Learn what the COOP header is and how it should be deployed.](https://link-to-background)',
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
  /** Summary text for the results of a Lighthouse audit that evaluates the COOP header for origin isolation. This is displayed if no COOP header is deployed. "COOP" stands for "Cross-Origin-Opener-Policy". */
=======
      '[Learn what the COOP header is and how it should be deployed.](https://link-to-background)',
  /**
     Summary text for the results of a Lighthouse audit that evaluates the COOP
     header for origin isolation. This is displayed if no COOP header is
     deployed. "COOP" stands for "Cross-Origin-Opener-Policy".
   */
>>>>>>> 4d7aa600b (Re-format origin isolation audit and enable it in the default config.)
=======
    '[Learn what the COOP header is and how it should be deployed.](https://link-to-background)',
=======
    '[Learn what the COOP header is and how it should be deployed.](https://web.dev/articles/why-coop-coep#coop)',
>>>>>>> 5abe53686 (Add second smokehouse test for a missing coop header.)
  /** Summary text for the results of a Lighthouse audit that evaluates the COOP header for origin isolation. This is displayed if no COOP header is deployed. "COOP" stands for "Cross-Origin-Opener-Policy". */
>>>>>>> 2afefff83 (Re-format COOP audit to pass some JS parsing.)
=======
    '[Learn what the COOP header is and how it should be deployed.](https://link-to-background)',
  /** Summary text for the results of a Lighthouse audit that evaluates the COOP header for origin isolation. This is displayed if no COOP header is deployed. "COOP" stands for "Cross-Origin-Opener-Policy". */
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
  noCoop: 'No COOP header found',
  /** Table item value calling out the presence of a syntax error. */
  invalidSyntax: 'Invalid syntax',
  /** Label for a column in a data table; entries will be a directive of the COOP header. "COOP" stands for "Cross-Origin-Opener-Policy". */
  columnDirective: 'Directive',
  /** Label for a column in a data table; entries will be the severity of an issue with the COOP header. "COOP" stands for "Cross-Origin-Opener-Policy". */
  columnSeverity: 'Severity',
};

const str_ = i18n.createIcuMessageFn(import.meta.url, UIStrings);

class OriginIsolation extends Audit {
  /**
   * @return {LH.Audit.Meta}
   */
  static get meta() {
    return {
      id: 'origin-isolation',
      scoreDisplayMode: Audit.SCORING_MODES.INFORMATIVE,
      title: str_(UIStrings.title),
      description: str_(UIStrings.description),
      requiredArtifacts: ['devtoolsLogs', 'URL'],
    };
  }


  /**
   * @param {LH.Artifacts} artifacts
   * @param {LH.Audit.Context} context
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
   * @return {Promise<coopHeaders: string[]>}
   */
  static async getRawCoop(artifacts, context) {
    const devtoolsLog = artifacts.devtoolsLogs[Audit.DEFAULT_PASS];
    const mainResource =
        await MainResource.request({devtoolsLog, URL: artifacts.URL}, context);

    let coopHeaders =
        mainResource.responseHeaders
            .filter(h => {
              return h.name.toLowerCase() === 'cross-origin-opener-policy';
            })
            .flatMap(h => h.value);

    // Sanitize the header value.
    coopHeaders = coopHeaders.map(v => v.toLowerCase().replace(/\s/g, ''));

    return coopHeaders;
=======
   * @return {Promise<{coopHeaders: string[]}>}
=======
   * @return {Promise<coopHeaders: string[]>}
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
   */
  static async getRawCoop(artifacts, context) {
    const devtoolsLog = artifacts.devtoolsLogs[Audit.DEFAULT_PASS];
    const mainResource =
        await MainResource.request({devtoolsLog, URL: artifacts.URL}, context);

    let coopHeaders =
        mainResource.responseHeaders
            .filter(h => {
              return h.name.toLowerCase() === 'cross-origin-opener-policy';
            })
            .flatMap(h => h.value);

    // Sanitize the header value.
    coopHeaders = coopHeaders.map(v => v.toLowerCase().replace(/\s/g, ''));

<<<<<<< HEAD
    return {coopHeaders};
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
    return coopHeaders;
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
=======
   * @return {Promise<{coopHeaders: string[]}>}
   */
  static async getRawCoop(artifacts, context) {
    const devtoolsLog = artifacts.devtoolsLogs[Audit.DEFAULT_PASS];
    const mainResource = await MainResource.request({devtoolsLog, URL: artifacts.URL}, context);

    var coopHeaders = mainResource.responseHeaders
      .filter(h => {
        return h.name.toLowerCase() === 'cross-origin-opener-policy';
      })
      .flatMap(h => h.value);

      // Sanitize the header value.
      coopHeaders = coopHeaders.map(v => v.toLowerCase().replace(/\s/g, ''));

    return {coopHeaders};
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
  }

  /**
   * @param {string | undefined} coopDirective
   * @param {LH.IcuMessage | string} findingDescription
   * @param {LH.IcuMessage=} severity
   * @return {LH.Audit.Details.TableItem}
   */
  static findingToTableItem(coopDirective, findingDescription, severity) {
    return {
      directive: coopDirective,
      description: findingDescription,
      severity,
    };
  }

  /**
   * @param {string[]} coopHeaders
   * @return {{score: number, results: LH.Audit.Details.TableItem[]}}
   */
  static constructResults(coopHeaders) {
    const rawCoop = [...coopHeaders];
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    const allowedDirectives =
        ['unsafe-none', 'same-origin-allow-popups', 'same-origin'];
=======
    const allowedDirectives = [ 'unsafe-none', 'same-origin-allow-popups', 'same-origin' ];
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
    const allowedDirectives =
        ['unsafe-none', 'same-origin-allow-popups', 'same-origin'];
>>>>>>> 4d7aa600b (Re-format origin isolation audit and enable it in the default config.)
=======
    const allowedDirectives = [ 'unsafe-none', 'same-origin-allow-popups', 'same-origin' ];
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
    const violations = [];
    const syntax = [];

    if (!rawCoop.length) {
      violations.push({
        severity: str_(i18n.UIStrings.itemSeverityHigh),
        description: str_(UIStrings.noCoop),
        directive: undefined,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
      });
=======
      })
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
      });
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
=======
      })
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
    }

    for (const actualDirective of coopHeaders) {
      // If there is a directive that's not an official COOP directive.
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
      if (!allowedDirectives.includes(actualDirective)) {
        syntax.push({
          severity: str_(i18n.UIStrings.itemSeverityLow),
          description: str_(UIStrings.invalidSyntax),
          directive: actualDirective,
        });
<<<<<<< HEAD
=======
      if(!allowedDirectives.includes(actualDirective)){
=======
      if (!allowedDirectives.includes(actualDirective)) {
>>>>>>> 4d7aa600b (Re-format origin isolation audit and enable it in the default config.)
=======
      if(!allowedDirectives.includes(actualDirective)){
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
        syntax.push({
          severity: str_(i18n.UIStrings.itemSeverityLow),
          description: str_(UIStrings.invalidSyntax),
          directive: actualDirective
        })
<<<<<<< HEAD
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
=======
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
      }
    }

    const results = [
      ...violations.map(
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
          f => this.findingToTableItem(
              f.directive, f.description,
              str_(i18n.UIStrings.itemSeverityHigh))),
=======
        f => this.findingToTableItem(
            f.directive, f.description,
            str_(i18n.UIStrings.itemSeverityHigh))),
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
          f => this.findingToTableItem(
              f.directive, f.description,
              str_(i18n.UIStrings.itemSeverityHigh))),
>>>>>>> 4d7aa600b (Re-format origin isolation audit and enable it in the default config.)
=======
        f => this.findingToTableItem(
            f.directive, f.description,
            str_(i18n.UIStrings.itemSeverityHigh))),
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
      ...syntax.map(
          f => this.findingToTableItem(
              f.directive, f.description,
              str_(i18n.UIStrings.itemSeverityLow))),
    ];

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    return {score: violations.length || syntax.length > 1 ? 0 : 1, results};
=======
    return {score: violations.length ? 0 : 1, results};
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
    return {score: violations.length || syntax.length > 1 ? 0 : 1, results};
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
=======
    return {score: violations.length ? 0 : 1, results};
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
  }

  /**
   * @param {LH.Artifacts} artifacts
   * @param {LH.Audit.Context} context
   * @return {Promise<LH.Audit.Product>}
   */
  static async audit(artifacts, context) {
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    const coopHeaders = await this.getRawCoop(artifacts, context);
=======
    const {coopHeaders} = await this.getRawCoop(artifacts, context);
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
=======
    const coopHeaders = await this.getRawCoop(artifacts, context);
>>>>>>> b2851bf51 (Adding changes to COOP audit similar to HSTS audit (recommendations from https://github.com/GoogleChrome/lighthouse/pull/16257).)
=======
    const {coopHeaders} = await this.getRawCoop(artifacts, context);
>>>>>>> 287296188 (Add Lighthouse audit to check for presence of the COOP header (origin isolation).)
    const {score, results} = this.constructResults(coopHeaders);

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

export default OriginIsolation;
export {UIStrings};
