/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0A0D14",
        surface: "#121824",
        card: "#161F30",
        border: "#232D42",
        primary: {
          DEFAULT: "#00F0FF",
          hover: "#00D8E6",
        },
        danger: {
          DEFAULT: "#FF3366",
          dark: "#D91B4C",
        },
        warning: {
          DEFAULT: "#FFB800",
          dark: "#CC9300",
        },
        success: {
          DEFAULT: "#00E676",
          dark: "#00B359",
        }
      }
    },
  },
  plugins: [],
}
