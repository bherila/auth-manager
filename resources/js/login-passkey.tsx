import { PasskeyLoginButton } from 'bwh-auth';
import React from 'react';
import { createRoot } from 'react-dom/client';

import { PasswordlessLogin } from './auth/passwordless-login';
import { getCsrfToken } from './auth/shared-components';
import { Button } from './components/ui/button';

const passkeyMount = document.getElementById('passkey-login-mount');
if (passkeyMount) {
  createRoot(passkeyMount).render(
    <PasskeyLoginButton components={{ Button }} endpoints={{ csrfToken: getCsrfToken() }} />,
  );
}

const passwordlessMount = document.getElementById('passwordless-login-mount');
if (passwordlessMount) {
  createRoot(passwordlessMount).render(<PasswordlessLogin />);
}
