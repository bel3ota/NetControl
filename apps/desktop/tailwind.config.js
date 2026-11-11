/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#05090D",
        raised: "#0A1119",
        panel: "#0D1620",
        "panel-2": "#111D29",
        line: "#1A2A38",
        "line-strong": "#274052",
        ink: "#E9F2F8",
        muted: "#8CA1B4",
        faint: "#5B7082",
        mint: "#3FE0AE",
        "mint-dim": "#1D6B58",
        azure: "#5C9DFF",
        violet: "#9B7DFF",
        amber: "#FFB454",
        rose: "#FF5E7D",
        success: "#45E39B",
      },
      fontFamily: {
        display: ["Space Grotesk", "Inter", "system-ui", "sans-serif"],
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Consolas", "monospace"],
      },
      boxShadow: {
        panel: "0 20px 60px -30px rgba(0,0,0,.9)",
        glow: "0 0 0 1px rgba(63,224,174,.25), 0 0 40px -12px rgba(63,224,174,.35)",
      },
      backgroundImage: {
        "grid-fade":
          "linear-gradient(rgba(63,224,174,.06) 1px, transparent 1px), linear-gradient(90deg, rgba(63,224,174,.06) 1px, transparent 1px)",
      },
      animation: {
        "pulse-soft": "pulseSoft 2.6s ease-in-out infinite",
        "fade-up": "fadeUp .45s cubic-bezier(.2,.8,.2,1)",
        sweep: "sweep 6s linear infinite",
      },
      keyframes: {
        pulseSoft: {
          "0%,100%": { opacity: "0.45", transform: "scale(1)" },
          "50%": { opacity: "1", transform: "scale(1.08)" },
        },
        fadeUp: {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        sweep: {
          from: { transform: "rotate(0deg)" },
          to: { transform: "rotate(360deg)" },
        },
      },
    },
  },
  plugins: [],
};
