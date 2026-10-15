// Injected by vite.config.js from PALANTIR_UI_ROLE / the tokens that are available.
// 'admin' -> write controls (register node, deactivate, investigate) are shown.
// It is only a UI hint: the backend still enforces roles from the Bearer token.
/* global __PALANTIR_UI_ROLE__ */
export const UI_ROLE = typeof __PALANTIR_UI_ROLE__ !== 'undefined' ? __PALANTIR_UI_ROLE__ : 'read';
export const CAN_WRITE = UI_ROLE === 'admin';
