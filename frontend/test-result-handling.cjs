const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

// Execute the actual App completion callback without a CDN or a browser.
const html = readFileSync(`${__dirname}/index.html`, 'utf8');
const callback = html.match(/const handleComplete = useCallback\(\(r\) => \{([\s\S]*?)\n      \}, \[\]\);/);
assert.ok(callback, 'The App completion callback must be present');

function complete(result) {
  const state = { phase: 'scanning' };
  vm.runInNewContext(`(function(r) {${callback[1]} })(result)`, {
    result,
    setResult(value) { state.result = value; },
    setPhase(value) { state.phase = value; },
    setErrorMsg(value) { state.error = value; },
  });
  return state;
}

test('an incomplete response uses the existing error and retry screen', () => {
  const state = complete({ error: 'Analysis incomplete. Please retry.', findings: [] });
  assert.equal(state.phase, 'error');
  assert.equal(state.error, 'Analysis incomplete. Please retry.');
  assert.equal(state.result, undefined);
});

test('partial findings cannot enter the complete report screen', () => {
  const state = complete({ error: 'Analysis incomplete.', findings: [{ title: 'Fixture' }] });
  assert.equal(state.phase, 'error');
  assert.equal(state.result, undefined);
});

test('successful results still enter the report screen', () => {
  const result = { error: null, findings: [] };
  const state = complete(result);
  assert.equal(state.phase, 'results');
  assert.equal(state.result, result);
});

test('an empty error message still uses the error screen', () => {
  assert.equal(complete({ error: '', findings: [] }).phase, 'error');
});
