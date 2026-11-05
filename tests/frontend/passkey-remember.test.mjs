import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { LOGIN_DOM, rememberLogin } from '../../resources/js/auth/login-dom.ts';

const originalDocument = globalThis.document;
afterEach(() => {
  if (originalDocument === undefined) delete globalThis.document;
  else globalThis.document = originalDocument;
});

test('a sign-in page without a remember control keeps passkeys session-only', () => {
  globalThis.document = { getElementById: () => null };
  assert.equal(rememberLogin(), false);
});

test('a pending passkey ceremony reads the current checkbox rather than its initial value', () => {
  let checkbox = { checked: false };
  globalThis.document = { getElementById: (id) => id === LOGIN_DOM.rememberInput ? checkbox : null };
  const choiceAtVerification = rememberLogin;
  assert.equal(choiceAtVerification(), false);
  checkbox.checked = true;
  assert.equal(choiceAtVerification(), true);
  checkbox = { checked: false };
  assert.equal(choiceAtVerification(), false);
});
