import assert from 'node:assert/strict';
import test from 'node:test';
import { CODE_LOCKED_MESSAGE, mapCodeError } from '../../resources/js/auth/login-errors.ts';

test('request throttles retain wait-and-retry guidance instead of locking code verification', () => {
  const message = 'Too many sign-in code requests. Please try again later.';
  assert.equal(mapCodeError(message), message);
  assert.equal(mapCodeError(new Error(message)), message);
  assert.notEqual(mapCodeError(message), CODE_LOCKED_MESSAGE);
});

test('verification throttles still explain how to get a fresh code', () => {
  assert.equal(mapCodeError('Too many incorrect codes.'), CODE_LOCKED_MESSAGE);
});
