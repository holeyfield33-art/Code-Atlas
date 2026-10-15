/**
 * Vue single-file-component (.vue) support.
 *
 * A .vue file mixes <template>, <script>/<script setup>, and <style>. Only the
 * script is analyzable code, so we hand the JS/TS (Babel) backend a POSITION-
 * PRESERVING shim: the <script> block's inner content is kept verbatim at its
 * original byte/line offsets, and everything else (template, style, tags) is
 * blanked to spaces with newlines preserved. Babel then parses the shim and
 * every node's line/column lands exactly where it does in the real .vue, so the
 * viewer/MCP highlight the right place and the inlined source stays the real file.
 */

const SCRIPT_RE = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;

/**
 * Return a JS/TS source the same length as `vue`, with only the <script> inner
 * content present (at original offsets) and all else blanked. Returns null when
 * the component has no <script> block (nothing to analyze).
 * Supports multiple blocks (e.g. `<script>` + `<script setup>`) and `lang="ts"`.
 */
export function extractVueScript(vue: string): string | null {
  // Base: same length, newlines kept (line parity), everything else a space.
  // Index by UTF-16 CODE UNIT (vue[i]), not code point — regex `.index`, string
  // `.length` and the offsets below are all code-unit based, so Array.from
  // (which iterates code points) would desync them whenever an astral char
  // (e.g. an emoji) appears before <script>, corrupting the shim. A lone
  // surrogate half is not "\n", so it blanks to a space: length stays identical.
  const arr: string[] = new Array(vue.length);
  for (let i = 0; i < vue.length; i++) arr[i] = vue[i] === "\n" ? "\n" : " ";
  let found = false;
  let m: RegExpExecArray | null;
  SCRIPT_RE.lastIndex = 0;
  while ((m = SCRIPT_RE.exec(vue)) !== null) {
    const inner = m[1];
    if (!inner) continue;
    const openLen = m[0].length - inner.length - "</script>".length; // length of `<script ...>`
    const innerStart = m.index + openLen;
    for (let i = 0; i < inner.length; i++) arr[innerStart + i] = inner[i]; // verbatim, newlines included
    found = true;
  }
  return found ? arr.join("") : null;
}
