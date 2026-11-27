// Fragment credentials never enter query strings, referrers, storage or DOM attributes.
const ticket = new URLSearchParams(location.hash.slice(1)).get('ticket');
history.replaceState(null, '', location.pathname);
const root = document.getElementById('test-login-confirm');
const status = document.getElementById('test-login-status');
const button = document.getElementById('test-login-continue') as HTMLButtonElement | null;
const csrf = document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]')?.content;

async function post(url: string): Promise<Record<string, unknown>> {
    const response = await fetch(url, {
        method: 'POST', credentials: 'same-origin', redirect: 'error',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRF-TOKEN': csrf ?? '' },
        body: JSON.stringify({ ticket }),
    });
    if (!response.ok) throw new Error('Synthetic sign-in expired. Return to the application to start again.');
    return await response.json() as Record<string, unknown>;
}

if (root && status && button && csrf) {
    const fail = (): void => {
        status.textContent = 'Synthetic sign-in expired. Return to the application to start again.';
        button.disabled = true;
    };
    if (!ticket || !/^[A-Za-z0-9_-]{43}$/.test(ticket)) fail();
    else void post(root.dataset.preview ?? '').then((data) => {
        if (typeof data.name !== 'string' || typeof data.application !== 'string') throw new Error('Invalid preview');
        status.textContent = `Sign in as ${data.name} to ${data.application}?`;
        button.disabled = false;
        button.addEventListener('click', () => {
            button.disabled = true;
            void post(root.dataset.confirm ?? '').then((result) => {
                if (typeof result.redirect_uri !== 'string' || !result.redirect_uri.startsWith('/') || result.redirect_uri.startsWith('//')) throw new Error('Invalid destination');
                location.assign(result.redirect_uri);
            }).catch(fail);
        }, { once: true });
    }).catch(fail);
}

export {};
