/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#FFFFFF",
        surface: "#F4F4F5",
        surfaceHighlight: "#E4E4E7",
        foreground: "#09090B",
        muted: "#71717A",
        border: "#E4E4E7",
        primary: "#0055FF",
        primaryForeground: "#FFFFFF",
        secondary: "#F4F4F5",
        secondaryForeground: "#18181B",
        accent: "#FF3333",
        accentForeground: "#FFFFFF",
        success: "#00CC66",
        warning: "#FFCC00",
        destructive: "#FF3333"
      },
      fontFamily: {
        heading: ['Chivo', 'sans-serif'],
        body: ['IBM Plex Sans', 'sans-serif'],
        code: ['JetBrains Mono', 'monospace']
      },
      letterSpacing: {
        tightest: '-0.02em',
        widest: '0.2em'
      },
      borderRadius: {
        none: '0px',
        sm: '2px'
      },
      backgroundImage: {
        'grid-pattern': 'linear-gradient(to right, #80808012 1px, transparent 1px), linear-gradient(to bottom, #80808012 1px, transparent 1px)'
      },
      backgroundSize: {
        'grid': '24px 24px'
      }
    }
  },
  plugins: [require("tailwindcss-animate")]
};