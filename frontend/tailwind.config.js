/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        brand: {
          black: '#09090b',
          surface: '#121215',
          subtle: '#18181b',
          border: '#27272a',
          hover: '#3f3f46',
          muted: '#a1a1aa',
          light: '#f4f4f5'
        }
      }
    }
  },
  plugins: [],
};
