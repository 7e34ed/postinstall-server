export default {
  content: [
    "../templates/**/*.html",
    "../apps/**/templates/**/*.html",
    "./src/**/*.{js,css}",
  ],
  theme: { extend: {} },
  plugins: [
    require("daisyui"),
    require("@tailwindcss/forms"),
    require("@tailwindcss/typography"),
  ],
  daisyui: {
    themes: ["dark", "light"],
    darkTheme: "dark",
  },
};