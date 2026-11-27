import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { authEndpoints } from '../../resources/js/lib/app-path.ts';

const originalDocument = globalThis.document;
afterEach(() => {
  if (originalDocument === undefined) delete globalThis.document;
  else globalThis.document = originalDocument;
});

for (const base of ['/', '/auth/', '/identity/accounts/']) {
  test(`confirmation endpoints stay in the server-rendered provider base ${base}`, () => {
    globalThis.document = { querySelector: (selector) => selector === 'meta[name="auth-manager-base"]' ? { getAttribute: () => base } : null };
    const prefix = base.replace(/\/+$/, '');
    const endpoints = authEndpoints('synthetic-csrf-token');
    assert.equal(endpoints.csrfToken, 'synthetic-csrf-token');
    assert.equal(endpoints.confirmPassword, `${prefix}/api/auth/confirm-password`);
    assert.equal(endpoints.passkeyConfirmOptions, `${prefix}/api/passkeys/confirm/options`);
    assert.equal(endpoints.passkeyConfirm, `${prefix}/api/passkeys/confirm`);
    assert.equal(endpoints.passkeyRegisterOptions, `${prefix}/api/passkeys/register/options`);
    assert.equal(endpoints.passkeyDelete('a/b'), `${prefix}/api/passkeys/a%2Fb`);
  });

  test(`an old RP choice changes only authentication options under ${base}`, () => {
    globalThis.document = { querySelector: () => ({ getAttribute: () => base }) };
    const normal = authEndpoints('synthetic-csrf-token');
    const related = authEndpoints('synthetic-csrf-token', 'app.example.test');
    assert.equal(related.passkeyAuthOptions, `${base.replace(/\/+$/, '')}/api/passkeys/auth/options?rp_id=app.example.test`);
    for (const key of ['passkeyAuth', 'passkeyRegisterOptions', 'passkeyRegister', 'passkeyConfirmOptions', 'passkeyConfirm', 'confirmPassword', 'csrfToken']) {
      assert.equal(related[key], normal[key]);
    }
  });
}
