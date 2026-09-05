import { LOGIN_DOM, loginEl } from './login-dom';

/**
 * Progressive show/hide password control. The button ships hidden in the
 * Blade markup and is revealed only once this runs, so a page without
 * JavaScript never shows a control that does nothing.
 */
export function enhancePasswordToggle(): void {
  const toggle = loginEl<HTMLButtonElement>(LOGIN_DOM.passwordToggle);
  const input = loginEl<HTMLInputElement>(LOGIN_DOM.passwordInput);
  if (!toggle || !input) return;

  const render = (visible: boolean): void => {
    input.type = visible ? 'text' : 'password';
    toggle.setAttribute('aria-pressed', visible ? 'true' : 'false');
    toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
    toggle.textContent = visible ? 'Hide' : 'Show';
  };

  toggle.addEventListener('click', () => {
    render(input.type === 'password');
    toggle.focus();
  });

  render(false);
  toggle.hidden = false;
}
