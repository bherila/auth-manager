import { PasskeySection } from 'bwh-auth';
import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';

import { getAuthComponents, getCsrfToken } from '@/auth/shared-components';

function PasskeyManagement(): React.JSX.Element {
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  return (
    <div className="space-y-4">
      {message ? <p className="text-sm text-success" role="status">{message}</p> : null}
      {error ? <p className="text-destructive text-sm" role="alert">{error}</p> : null}
      <PasskeySection
        components={getAuthComponents()}
        endpoints={{ csrfToken: getCsrfToken() }}
        onSuccess={(nextMessage) => {
          setError('');
          setMessage(nextMessage);
        }}
        onError={(_field, nextError) => {
          setMessage('');
          setError(nextError);
        }}
      />
    </div>
  );
}

const mount = document.getElementById('passkey-management-mount');
if (mount) {
  createRoot(mount).render(<PasskeyManagement />);
}
