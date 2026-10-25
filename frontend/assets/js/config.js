// Runtime configuration for the static frontend.
// apiBase: "" means the API is on the same origin (local dev, or a Netlify /api/* proxy).
// Set it to e.g. "https://vev-audit-api.onrender.com" to call a backend on another origin
// (that backend must list this site in VEV_CORS_ORIGINS). scripts/netlify-build.sh can write this file.
window.VEV_CONFIG = {
  apiBase: "",
};
