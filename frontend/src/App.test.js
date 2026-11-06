import { render, screen } from '@testing-library/react';
import Login from './components/Login';

test('renders TrustVault authentication interface', () => {
  render(<Login onLoginSuccess={() => {}} />);
  
  // Heading check
  const heading = screen.getByRole('heading', { level: 2 });
  expect(heading).toBeInTheDocument();
  expect(heading.textContent).toContain('TrustVault');

  // Input check
  const emailInput = screen.getByPlaceholderText(/user@example\.com/i);
  expect(emailInput).toBeInTheDocument();

  // Button check
  const submitBtn = screen.getByRole('button', { name: /sign in securely/i });
  expect(submitBtn).toBeInTheDocument();
});
