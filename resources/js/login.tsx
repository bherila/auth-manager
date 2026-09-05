import React from 'react';
import { createRoot } from 'react-dom/client';

import { EmailCodeLogin } from './auth/email-code-login';
import { LOGIN_DOM, loginEl } from './auth/login-dom';
import { PasskeyLogin } from './auth/passkey-login';
import { enhancePasswordToggle } from './auth/password-toggle';

const passkeyMount = loginEl(LOGIN_DOM.passkeyMount);
if (passkeyMount) {
  createRoot(passkeyMount).render(<PasskeyLogin />);
}

const emailCodeMount = loginEl(LOGIN_DOM.emailCodeMount);
if (emailCodeMount) {
  createRoot(emailCodeMount).render(<EmailCodeLogin />);
}

enhancePasswordToggle();
