/**
 * @license
 * Copyright 2016 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from 'assert/strict';

import {parseManifest} from '../../lib/manifest-parser.js';
import {readJson} from '../test-utils.js';

const manifestStub = readJson('../fixtures/manifest.json', import.meta);

const EXAMPLE_MANIFEST_URL = 'https://example.com/manifest.json';
const EXAMPLE_DOC_URL = 'https://example.com/index.html';
const EXAMPLE_MANIFEST_BLOB_URL = 'blob:https://example.com/manifest.json';

/**
 * Simple manifest parsing helper when the manifest URLs aren't material to the
 * test. Uses example.com URLs for testing.
 * @param {string} manifestSrc
 * @return {!ManifestNode<(!Manifest|undefined)>}
 */
function noUrlManifestParser(manifestSrc) {
  return parseManifest(manifestSrc, EXAMPLE_MANIFEST_URL, EXAMPLE_DOC_URL);
}

describe('Manifest Parser', function() {
  it('should not parse empty string input', function() {
    const parsedManifest = noUrlManifestParser('');
    expect(parsedManifest.warning)
      .toEqual('ERROR: file isn\'t valid JSON: SyntaxError: Unexpected end of JSON input');
  });

  it('accepts empty dictionary', function() {
    const parsedManifest = noUrlManifestParser('{}');
    expect(parsedManifest.warning).toBeUndefined();
    expect(parsedManifest.value.name.value).toBe(undefined);
    expect(parsedManifest.value.short_name.value).toBe(undefined);
    expect(parsedManifest.value.start_url.value).toBe(EXAMPLE_DOC_URL);
    expect(parsedManifest.value.display.value).toBe('browser');
    expect(parsedManifest.value.orientation.value).toBe(undefined);
    expect(parsedManifest.value.theme_color.value).toBe(undefined);
    expect(parsedManifest.value.background_color.value).toBe(undefined);
    expect(parsedManifest.value.icons.value).toHaveLength(0);
    // TODO:
    // related_applications
    // prefer_related_applications
  });

  it('should warn on invalid manifest parser URL', function() {
    const parsedManifest = parseManifest('{}', 'not a URL', EXAMPLE_DOC_URL);
    expect(parsedManifest.warning)
      .toEqual('ERROR: invalid manifest URL: \'not a URL\'');
  });

  it('should warn on valid but non-(HTTP|HTTPS) manifest parser URL', function() {
    const parsedManifest = parseManifest('{}', EXAMPLE_MANIFEST_BLOB_URL, EXAMPLE_DOC_URL);
    expect(parsedManifest.warning)
      .toEqual('WARNING: manifest URL not available over a valid network protocol');
  });

  describe('icon parsing', function() {
    // 9.7
    it('gives an empty array and an error for erroneous icons entry', () => {
      const parsedManifest = parseManifest(
        '{"icons": {"16": "img/icons/icon16.png"}}',
        EXAMPLE_MANIFEST_URL,
        EXAMPLE_DOC_URL
      );

      expect(parsedManifest.warning).toBeUndefined();
      const icons = parsedManifest.value.icons;
      assert.ok(Array.isArray(icons.value));
      assert.equal(icons.value.length, 0);
      assert.ok(icons.warning);
    });

    it('gives an empty array and no error for missing icons entry', () => {
      const parsedManifest = parseManifest('{}', EXAMPLE_MANIFEST_URL, EXAMPLE_DOC_URL);
      expect(parsedManifest.warning).toBeUndefined();
      const icons = parsedManifest.value.icons;
      assert.ok(Array.isArray(icons.value));
      assert.equal(icons.value.length, 0);
      assert.ok(!icons.warning);
    });

    it('parses basic string', function() {
      const parsedManifest = parseManifest(
        '{"icons": [{"src": "192.png", "sizes": "192x192"}]}',
        EXAMPLE_MANIFEST_URL,
        EXAMPLE_DOC_URL
      );
      expect(parsedManifest.warning).toBeUndefined();
      const icons = parsedManifest.value.icons;
      assert(!icons.warning);
      const icon192 = icons.value[0];
      assert(!icon192.value.sizes.warning);
      assert.equal(icons.value.length, 1);
    });

    it('finds four icons in the stub manifest', function() {
      const parsedManifest = parseManifest(
        JSON.stringify(manifestStub),
        EXAMPLE_MANIFEST_URL,
        EXAMPLE_DOC_URL
      );
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.icons.value.length, 4);
    });

    it('parses icons with extra whitespace', function() {
      const manifest = '{"icons": [{"src": "192.png", "sizes": " 192x192   256x256"}]}';
      const parsedManifest = parseManifest(manifest, EXAMPLE_MANIFEST_URL, EXAMPLE_DOC_URL);
      const icons = parsedManifest.value.icons;
      const icon192 = icons.value[0];
      const icon192Sizes = icon192.value.sizes.value;
      assert.equal(icon192Sizes[0], '192x192');
      assert.equal(icon192Sizes[1], '256x256');
    });

    it('parses icons and discards any with invalid src values', () => {
      const manifestSrc = JSON.stringify({
        icons: [{
          src: {},
        }, {
          src: 17,
        }],
      });
      const parsedManifest = parseManifest(manifestSrc, EXAMPLE_MANIFEST_URL, EXAMPLE_DOC_URL);
      const icons = parsedManifest.value.icons;
      assert.equal(icons.value.length, 0);
    });

    it('parses icons and discards any with invalid base URL values', () => {
      const manifestSrc = JSON.stringify({
        icons: [{
          src: '/valid/path',
        }],
      });
      const parsedManifest = parseManifest(manifestSrc, EXAMPLE_MANIFEST_BLOB_URL,
        EXAMPLE_DOC_URL);
      const icons = parsedManifest.value.icons;
      expect(icons.value).toHaveLength(0);
      expect(icons.warning).toEqual('WARNING: Some icons were ignored due to warnings.');
    });

    it('parses icons and discards any with undefined or empty string src values', () => {
      const manifestSrc = JSON.stringify({
        icons: [{
          src: '',
        }, {}],
      });
      const parsedManifest = parseManifest(manifestSrc, EXAMPLE_MANIFEST_URL, EXAMPLE_DOC_URL);
      const icons = parsedManifest.value.icons;
      assert.equal(icons.value.length, 0);
    });

    it('constructs icon URLs relative to manifest URL ', () => {
      const manifestSrc = JSON.stringify({
        icons: [{
          src: '../cool.gif',
        }],
      });
      const manifestUrl = 'https://example.com/resources/manifest.webmanifest';
      const parsedManifest = parseManifest(manifestSrc, manifestUrl, EXAMPLE_DOC_URL);
      const icons = parsedManifest.value.icons;
      assert.equal(icons.value.length, 1);
      const icon = icons.value[0].value;
      assert.equal(icon.src.value, 'https://example.com/cool.gif');
    });
  });

  describe('name parsing', function() {
    it('parses basic string', function() {
      const parsedManifest = noUrlManifestParser('{"name":"foo"}');
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.name.value, 'foo');
    });

    it('trims whitespaces', function() {
      const parsedManifest = noUrlManifestParser('{"name":" foo "}');
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.name.value, 'foo');
    });

    it('doesn\'t parse non-string', function() {
      let parsedManifest = noUrlManifestParser('{"name": {} }');
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.name.value, undefined);

      parsedManifest = noUrlManifestParser('{"name": 42 }');
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.name.value, undefined);
    });
  });

  describe('short_name parsing', function() {
    it('parses basic string', function() {
      const parsedManifest = noUrlManifestParser('{"short_name":"foo"}');
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.short_name.value, 'foo');
    });

    it('trims whitespaces', function() {
      const parsedManifest = noUrlManifestParser('{"short_name":" foo "}');
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.short_name.value, 'foo');
    });

    it('doesn\'t parse non-string', function() {
      let parsedManifest = noUrlManifestParser('{"short_name": {} }');
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.short_name.value, undefined);

      parsedManifest = noUrlManifestParser('{"short_name": 42 }');
      expect(parsedManifest.warning).toBeUndefined();
      assert.equal(parsedManifest.value.short_name.value, undefined);
    });
  });

  /**
   * @see https://w3c.github.io/manifest/#start_url-member
   */
  describe('start_url parsing', () => {
    // 8.10(3)
    it('falls back to document URL and issues a warning for a non-string', () => {
      const manifestSrc = JSON.stringify({
        start_url: {},
      });
      const manifestUrl = 'https://example.com/manifest.json';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(parsedUrl.warning);
      assert.equal(parsedUrl.value, docUrl);
    });

    it('falls back to document URL and issues a warning for a non-string', () => {
      const manifestSrc = JSON.stringify({
        start_url: 6,
      });
      const manifestUrl = 'https://example.com/manifest.json';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(parsedUrl.warning);
      assert.equal(parsedUrl.value, docUrl);
    });

    it('falls back to document URL and issues a warning for an empty string', () => {
      const manifestSrc = JSON.stringify({
        start_url: '',
      });
      const manifestUrl = 'https://example.com/manifest.json';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(parsedUrl.warning);
      assert.equal(parsedUrl.value, docUrl);
    });

    it('falls back to document URL and issues no warning when undefined', () => {
      const manifestSrc = JSON.stringify({});
      const manifestUrl = 'https://example.com/manifest.json';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(!parsedUrl.warning);
      assert.equal(parsedUrl.value, docUrl);
    });

    // 8.10(5)
    it('falls back to document URL and issues a warning for an invalid URL', () => {
      // `new URL('/manifest.json', '')` is invalid and will throw.
      const manifestSrc = JSON.stringify({
        start_url: '/manifest.json',
      });
      const manifestUrl = '';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(parsedUrl.warning);
      assert.equal(parsedUrl.value, docUrl);
    });

    // 8.10(6)
    it('falls back to document URL with warning when on different domain from document URL', () => {
      const manifestSrc = JSON.stringify({
        start_url: 'https://evil.com/index.html',
      });
      const manifestUrl = 'https://example.com/manifest.json';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(parsedUrl.warning);
      assert.equal(parsedUrl.value, docUrl);
    });

    it('falls back to document URL with warning when on different port from document URL', () => {
      const manifestSrc = JSON.stringify({
        start_url: 'https://example.com:314/index.html',
      });
      const manifestUrl = 'https://example.com/manifest.json';
      const docUrl = 'https://example.com:8080/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(parsedUrl.warning);
      assert.equal(parsedUrl.value, docUrl);
    });

    it('falls back to document URL with warning when on different scheme from document URL', () => {
      const manifestSrc = JSON.stringify({
        start_url: 'http://example.com/index.html',
      });
      const manifestUrl = 'https://example.com/manifest.json';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(parsedUrl.warning);
      assert.equal(parsedUrl.value, docUrl);
    });

    it('correctly parses a start_url of "/" relative to the manifest\'s url', () => {
      const manifestSrc = JSON.stringify({
        start_url: '/',
      });
      const manifestUrl = 'https://example.com/manifest.json';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(!parsedUrl.warning);
      assert.equal(parsedUrl.value, 'https://example.com/');
    });

    it('correctly parses a start_url relative to the manifest\'s url', () => {
      // from non-normative example in spec
      const manifestSrc = JSON.stringify({
        start_url: '../start_point.html',
      });
      const manifestUrl = 'https://example.com/resources/manifest.webmanifest';
      const docUrl = 'https://example.com/index.html';

      const parsedManifest = parseManifest(manifestSrc, manifestUrl, docUrl);
      const parsedUrl = parsedManifest.value.start_url;
      assert.ok(!parsedUrl.warning);
      assert.equal(parsedUrl.value, 'https://example.com/start_point.html');
    });
  });

  /**
   * @see https://w3c.github.io/manifest/#display-member
   */
  describe('display parsing', () => {
    it('falls back to \'browser\' and issues a warning for an invalid value', () => {
      const parsedManifest = noUrlManifestParser('{"display": {} }');
      const display = parsedManifest.value.display;
      assert.ok(display.warning);
      assert.equal(display.value, 'browser');
    });

    it('falls back to \'browser\' and issues a warning for an invalid value', () => {
      const parsedManifest = noUrlManifestParser('{"display": 5 }');
      const display = parsedManifest.value.display;
      assert.ok(display.warning);
      assert.equal(display.value, 'browser');
    });

    it('falls back to \'browser\' and issues no warning when undefined', () => {
      const parsedManifest = noUrlManifestParser('{}');
      const display = parsedManifest.value.display;
      assert.ok(!display.warning);
      assert.equal(display.value, 'browser');
    });

    it('trims whitespace', () => {
      const displayValue = ' fullscreen     ';
      const parsedManifest = noUrlManifestParser(`{"display": "${displayValue}" }`);
      const display = parsedManifest.value.display;
      assert.ok(!display.warning);
      assert.equal(display.value, 'fullscreen');
    });

    it('converts to lowercase', () => {
      const displayValue = 'fUlLScrEEn';
      const parsedManifest = noUrlManifestParser(`{"display": "${displayValue}" }`);
      const display = parsedManifest.value.display;
      assert.ok(!display.warning);
      assert.equal(display.value, 'fullscreen');
    });

    it('falls back to \'browser\' and issues a warning when a non-existent mode', () => {
      const parsedManifest = noUrlManifestParser('{"display": "fullestscreen" }');
      const display = parsedManifest.value.display;
      assert.ok(display.warning);
      assert.equal(display.value, 'browser');
    });

    it('correctly parses `fullscreen` display mode', () => {
      const parsedManifest = noUrlManifestParser('{"display": "fullscreen" }');
      const display = parsedManifest.value.display;
      assert.ok(!display.warning);
      assert.equal(display.value, 'fullscreen');
    });

    it('correctly parses `standalone` display mode', () => {
      const parsedManifest = noUrlManifestParser('{"display": "standalone" }');
      const display = parsedManifest.value.display;
      assert.ok(!display.warning);
      assert.equal(display.value, 'standalone');
    });

    it('correctly parses `minimal-ui` display mode', () => {
      const parsedManifest = noUrlManifestParser('{"display": "minimal-ui" }');
      const display = parsedManifest.value.display;
      assert.ok(!display.warning);
      assert.equal(display.value, 'minimal-ui');
    });

    it('correctly parses `browser` display mode', () => {
      const parsedManifest = noUrlManifestParser('{"display": "browser" }');
      const display = parsedManifest.value.display;
      assert.ok(!display.warning);
      assert.equal(display.value, 'browser');
    });
  });

  /**
   * @see https://w3c.github.io/manifest/#related_applications-member
   */
  describe('related_applications parsing', () => {
    it('correctly parses the urls from an example manifest', () => {
      // non normative-example from section 10
      const exampleManifest = {
        related_applications: [{
          platform: 'play',
          url: 'https://play.google.com/store/apps/details?id=com.example.app1',
          id: 'com.example.app1',
        }, {
          platform: 'itunes',
          url: 'https://itunes.apple.com/app/example-app1/id123456789',
        }],
      };


      const parsedManifest = parseManifest(JSON.stringify(exampleManifest), EXAMPLE_MANIFEST_URL,
          EXAMPLE_DOC_URL);
      const applications = parsedManifest.value.related_applications.value;
      assert.equal(applications.length, 2);
      const url0 = applications[0].value.url.value;
      assert.equal(url0, exampleManifest.related_applications[0].url);
      const url1 = applications[1].value.url.value;
      assert.equal(url1, exampleManifest.related_applications[1].url);
    });

    it('handles applications with invalid urls', () => {
      const exampleManifest = {
        related_applications: [{
          platform: 'play',
          url: 6,
          id: 'com.example.app1',
        }, {
          platform: 'itunes',
          url: {},
        }],
      };


      const parsedManifest = parseManifest(JSON.stringify(exampleManifest), EXAMPLE_MANIFEST_URL,
          EXAMPLE_DOC_URL);
      const applications = parsedManifest.value.related_applications.value;
      // First entry's url should be discarded but entry preserved due to valid id.
      // Second entry should be discarded since discarded url and no id.
      assert.equal(applications.length, 1);
      const url0 = applications[0].value.url.value;
      assert.equal(url0, undefined);
    });
  });

  describe('background_color, theme_color', () => {
    /**
     * Create a manifest with the specified colors and return the parsed result.
     * @param {string} backgroundColor
     * @param {string} themeColor
     */
    function getParsedManifest(backgroundColor, themeColor) {
      return parseManifest(`{
        "background_color": "${backgroundColor}",
        "theme_color": "${themeColor}"
      }`, EXAMPLE_MANIFEST_URL, EXAMPLE_DOC_URL);
    }

    it('correctly parses hex colors', () => {
      const bgColor = '#123';
      const themeColor = '#1a5e25';
      const parsedManifest = getParsedManifest(bgColor, themeColor).value;

      assert.strictEqual(parsedManifest.background_color.value, bgColor);
      assert.strictEqual(parsedManifest.background_color.warning, undefined);
      assert.strictEqual(parsedManifest.theme_color.value, themeColor);
      assert.strictEqual(parsedManifest.theme_color.warning, undefined);
    });

    it('correctly parses CSS3 and CSS4 nickname colors', () => {
      const bgColor = 'cornflowerblue';
      const themeColor = 'rebeccapurple'; // <3
      const parsedManifest = getParsedManifest(bgColor, themeColor).value;

      assert.strictEqual(parsedManifest.background_color.value, bgColor);
      assert.strictEqual(parsedManifest.background_color.warning, undefined);
      assert.strictEqual(parsedManifest.theme_color.value, themeColor);
      assert.strictEqual(parsedManifest.theme_color.warning, undefined);
    });

    it('correctly parses RGB/RGBA colors', () => {
      const bgColor = 'rgb(222, 184, 135)';
      const themeColor = 'rgba(5%, 10%, 20%, 0.4)';
      const parsedManifest = getParsedManifest(bgColor, themeColor).value;

      assert.strictEqual(parsedManifest.background_color.value, bgColor);
      assert.strictEqual(parsedManifest.background_color.warning, undefined);
      assert.strictEqual(parsedManifest.theme_color.value, themeColor);
      assert.strictEqual(parsedManifest.theme_color.warning, undefined);
    });

    it('correctly parses HSL/HSLA colors', () => {
      const bgColor = 'hsl(120, 100%, 50%)';
      const themeColor = 'hsla(120, 20%, 56%, 0.4)';
      const parsedManifest = getParsedManifest(bgColor, themeColor).value;

      assert.strictEqual(parsedManifest.background_color.value, bgColor);
      assert.strictEqual(parsedManifest.background_color.warning, undefined);
      assert.strictEqual(parsedManifest.theme_color.value, themeColor);
      assert.strictEqual(parsedManifest.theme_color.warning, undefined);
    });

    it('warns when colors are not strings', () => {
      const bgColor = 15;
      const themeColor = false;
      const parsedManifest = parseManifest(`{
        "background_color": ${bgColor},
        "theme_color": ${themeColor}
      }`, EXAMPLE_MANIFEST_URL, EXAMPLE_DOC_URL).value;

      assert.deepStrictEqual(parsedManifest.background_color, {
        raw: bgColor,
        value: undefined,
        warning: 'ERROR: expected a string.',
      });
      assert.deepStrictEqual(parsedManifest.theme_color, {
        raw: themeColor,
        value: undefined,
        warning: 'ERROR: expected a string.',
      });
    });
  });
});
