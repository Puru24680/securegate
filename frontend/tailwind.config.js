/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#F8FAFC',
        surface: '#FFFFFF',
        'surface-subtle': '#F1F5F9',
        border: '#E2E8F0',
        'border-light': '#F1F5F9',
        'gate-pass': '#10b981',
        'gate-review': '#f59e0b',
        'gate-block': '#ef4444',
        brand: {
          50: '#ecfdf5',
          100: '#d1fae5',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
          900: '#064e3b',
        },
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#f59e0b',
          low: '#0ea5e9',
          informational: '#64748b',
        }
      },
      fontFamily: {
        display: [
          'Manrope',
          '-apple-system',
          'sans-serif',
        ],
        sans: [
          'Manrope',
          '-apple-system',
          'sans-serif',
        ],
        mono: [
          'Manrope',
          '-apple-system',
          'sans-serif',
        ],
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.02), 0 1px 2px -1px rgba(0, 0, 0, 0.02)',
        'card-hover': '0 10px 25px -5px rgba(0, 0, 0, 0.04), 0 8px 10px -6px rgba(0, 0, 0, 0.02)',
        'card-elevated': '0 20px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01)',
        'pill': '0 2px 6px rgba(16, 185, 129, 0.2)',
      },
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.5rem',
        '4xl': '2rem',
      }
    },
  },
  plugins: [],
};
