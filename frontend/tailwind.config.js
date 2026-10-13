/** Tailwind v3 config for the GritScan console (built by Trunk's tailwind-css pipeline). */
module.exports = {
  content: ["./index.html", "./src/**/*.{rs,html,js}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['ui-monospace', '"Cascadia Code"', '"SF Mono"', 'Menlo', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};
