import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace']
      },
      colors: {
        ink: '#14232b',
        reef: '#0f766e',
        signal: '#b42318',
        wire: '#d8e1e8'
      },
      boxShadow: {
        panel: '0 1px 2px rgb(15 23 42 / 0.08)'
      }
    }
  },
  plugins: []
} satisfies Config;
