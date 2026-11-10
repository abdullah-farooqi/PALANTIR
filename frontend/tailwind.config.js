/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0A0B0D',
        surface: {
          DEFAULT: '#14171B',
          raised: '#1B1F24',
          overlay: '#21262D',
        },
        border: {
          DEFAULT: '#262B32',
          subtle: '#1D2126',
          active: '#3D444F',
        },
        fg: {
          DEFAULT: '#E8EAED',
          muted: '#8B93A0',
          dim: '#656C77',
        },
        lime: {
          DEFAULT: '#C6FF00',
          hover: '#D8FF4D',
          pressed: '#A8DB00',
          contrast: '#0A0B0D',
        },
        alert: {
          crit: {
            DEFAULT: '#E5484D',
            text: '#FFA4A7',
            bg: 'rgba(229, 72, 77, 0.12)',
            border: 'rgba(229, 72, 77, 0.40)',
          },
          med: {
            DEFAULT: '#F5A524',
            text: '#FFD485',
            bg: 'rgba(245, 165, 36, 0.12)',
            border: 'rgba(245, 165, 36, 0.40)',
          },
        },
      },
      fontFamily: {
        sans: ['"Space Grotesk"', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        'lime-glow': '0 0 14px rgba(198, 255, 0, 0.35)',
        'focus-ring': '0 0 0 2px #0A0B0D, 0 0 0 4px #C6FF00',
      },
      borderRadius: {
        instrument: '4px',
      },
    },
  },
  plugins: [],
};
