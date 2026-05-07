/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      borderRadius: {
        sm: '2px',
        DEFAULT: '3px',
        md: '4px',
        lg: '6px',
      },
      colors: {
        surface: {
          body: 'var(--color-surface-body)',
          card: 'var(--color-surface-card)',
          input: 'var(--color-surface-input)',
          hover: 'var(--color-surface-hover)',
          terminal: 'var(--color-surface-terminal)',
        },
        border: {
          DEFAULT: 'var(--color-border)',
          subtle: 'var(--color-border-subtle)',
        },
        content: {
          primary: 'var(--color-content-primary)',
          secondary: 'var(--color-content-secondary)',
          muted: 'var(--color-content-muted)',
          terminal: 'var(--color-content-terminal, var(--color-content-primary))',
        },
        accent: {
          DEFAULT: 'var(--color-accent)',
          hover: 'var(--color-accent-hover)',
          secondary: 'var(--color-accent-secondary)',
          'secondary-hover': 'var(--color-accent-secondary-hover)',
          tertiary: 'var(--color-accent-tertiary)',
          'tertiary-hover': 'var(--color-accent-tertiary-hover)',
        },
        semantic: {
          success: 'var(--color-semantic-success)',
          error: 'var(--color-semantic-error)',
          'error-bg': 'var(--color-semantic-error-bg)',
          'error-hover': 'var(--color-semantic-error-hover)',
          info: 'var(--color-semantic-info)',
          warning: 'var(--color-semantic-warning)',
          special: 'var(--color-semantic-special)',
        },
      },
    },
  },
  plugins: [],
}
