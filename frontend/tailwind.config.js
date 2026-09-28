/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // 丰图青(§13 品牌色 #0E7C7B 系)
        brand: {
          DEFAULT: "#0E7C7B",
          dark: "#0A5F5E",
          light: "#E6F4F3",
          soft: "#9CCFCE",
        },
        paper: "#FAFAF8", // 米白底
        ink: "#2B2F33",
        mute: "#6B7280",
      },
      boxShadow: {
        card: "0 1px 3px rgba(20, 30, 30, 0.06), 0 6px 18px rgba(20, 30, 30, 0.06)",
        lift: "0 4px 12px rgba(14, 124, 123, 0.12), 0 12px 32px rgba(14, 124, 123, 0.10)",
      },
      borderRadius: {
        card: "14px",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
