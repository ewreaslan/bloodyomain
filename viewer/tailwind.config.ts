import type { Config } from "tailwindcss"

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: "#06080c",
          card: "#0b0f18",
          elevated: "#101520",
          hover: "#161c2a",
        },
        border: {
          DEFAULT: "rgba(255,255,255,0.05)",
          glow: "rgba(255,255,255,0.08)",
        },
        accent: {
          cyan: "#00b4d8",
          blue: "#3b82f6",
          green: "#22c55e",
          yellow: "#eab308",
          orange: "#f59e0b",
          red: "#ef4444",
          purple: "#8b5cf6",
        },
        text: {
          primary: "#e8edf5",
          secondary: "#8895a8",
          muted: "#566077",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      animation: {
        "fade-in": "fadeIn 0.3s ease",
        "slide-up": "slideUp 0.35s ease-out",
        "pulse-glow": "pulseGlow 2s ease-in-out infinite",
        shimmer: "shimmer 2s infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulseGlow: {
          "0%, 100%": { boxShadow: "0 0 4px var(--tw-shadow-color)" },
          "50%": { boxShadow: "0 0 16px var(--tw-shadow-color)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
    },
  },
  plugins: [],
}

export default config
