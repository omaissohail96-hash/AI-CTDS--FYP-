/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#0B0D11',
        'bg-secondary': '#12151C',
        'bg-card': '#161A22',
        'accent': '#FF5A36',
        'accent-2': '#FF8C42',
        'cyber-warning': '#FFC857',
        'cyber-danger': '#FF3D57',
        'cyber-success': '#36D399',
        'cyber-info': '#5AA9FF',
        'border-subtle': 'rgba(255,255,255,0.06)',
      },
      fontFamily: {
        inter: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'glow-orange': '0 0 20px rgba(255,90,54,0.3)',
        'glow-orange-lg': '0 0 40px rgba(255,90,54,0.4)',
        'glow-red': '0 0 20px rgba(255,61,87,0.3)',
        'glow-green': '0 0 20px rgba(54,211,153,0.3)',
        'card': '0 4px 24px rgba(0,0,0,0.4)',
        'card-hover': '0 8px 40px rgba(0,0,0,0.6)',
      },
      animation: {
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.4s ease-out',
        'count-up': 'countUp 0.6s ease-out',
        'spin-slow': 'spin 3s linear infinite',
        'scan-line': 'scanLine 2s ease-in-out infinite',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 10px rgba(255,90,54,0.3)' },
          '50%': { boxShadow: '0 0 30px rgba(255,90,54,0.7)' },
        },
        slideIn: {
          from: { opacity: 0, transform: 'translateY(-10px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
        fadeIn: {
          from: { opacity: 0 },
          to: { opacity: 1 },
        },
        countUp: {
          from: { transform: 'translateY(20px)', opacity: 0 },
          to: { transform: 'translateY(0)', opacity: 1 },
        },
        scanLine: {
          '0%': { transform: 'scaleX(0)', opacity: 1 },
          '50%': { transform: 'scaleX(1)', opacity: 0.8 },
          '100%': { transform: 'scaleX(0)', opacity: 0 },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
