#!/usr/bin/env node
'use strict';

const fs = require('fs');
const html = fs.readFileSync('Web/console.html', 'utf8');
const ids = new Set();
for (const match of html.matchAll(/\bid="([^"]+)"/g)) {
  if (ids.has(match[1])) throw new Error(`duplicate element id: ${match[1]}`);
  ids.add(match[1]);
}

const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/gi)];
if (!scripts.length) throw new Error('no inline script found');
for (const script of scripts) {
  if (/\bsrc\s*=/.test(script[1])) throw new Error('external scripts are not allowed');
  new Function(script[2]);
  for (const reference of script[2].matchAll(/\$\('([^']+)'\)/g)) {
    if (!ids.has(reference[1])) throw new Error(`script references missing id: ${reference[1]}`);
  }
}
if (/<(?:script|link)[^>]+https?:\/\//i.test(html)) throw new Error('external Web dependencies are not allowed');
console.log(`web-console-ok: ${ids.size} ids, ${scripts.length} inline script`);
