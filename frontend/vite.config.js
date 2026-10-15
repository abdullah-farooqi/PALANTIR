// PALANTIR UI dev/preview server.
//
// The backend requires `Authorization: Bearer <token>` on every /api/v1 route
// (see backend/core/api_auth.py). In production Caddy injects that header after
// Authentik login. For local development THIS file plays the same role: the
// Vite proxy adds the token server-side, so it never ends up in the browser
// bundle.
//
// Config (read from the shell, frontend/.env.local, or the repo-root .env):
//   PALANTIR_API_TARGET     backend URL            (default http://127.0.0.1:8000)
//   PALANTIR_API_READ_TOKEN  read-only token        (same name as the backend .env)
//   PALANTIR_API_ADMIN_TOKEN admin token            (needed to add/remove nodes, run investigations)
//   PALANTIR_UI_ROLE        'read' (default) | 'admin'  -> which token the proxy sends
//   PALANTIR_UI_PORT        dev server port         (default 3000)
//   PALANTIR_AUTH_MODE      'token' (default) | 'none' (do not inject a header, e.g. when Caddy/Authentik does it)
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(({ mode }) => {
  // Repo-root .env first, then frontend/.env*, then real environment variables win.
  const env = {
    ...loadEnv(mode, path.resolve(here, '..'), ''),
    ...loadEnv(mode, here, ''),
    ...Object.fromEntries(Object.entries(process.env).filter(([, v]) => v !== undefined)),
  };

  const target = env.PALANTIR_API_TARGET || 'http://127.0.0.1:8000';
  const authMode = env.PALANTIR_AUTH_MODE || 'token';
  const wantedRole = (env.PALANTIR_UI_ROLE || 'read').toLowerCase() === 'admin' ? 'admin' : 'read';
  const tokens = { read: env.PALANTIR_API_READ_TOKEN || '', admin: env.PALANTIR_API_ADMIN_TOKEN || '' };

  // Fall back to whichever token exists so the UI still works with a single token.
  let role = wantedRole;
  if (!tokens[role]) role = role === 'admin' ? 'read' : 'admin';
  const token = authMode === 'none' ? '' : tokens[role];
  const effectiveRole = authMode === 'none' ? wantedRole : token ? role : 'none';

  if (authMode !== 'none' && !token) {
    // eslint-disable-next-line no-console
    console.warn(
      '\n[palantir-ui] No PALANTIR_API_READ_TOKEN / PALANTIR_API_ADMIN_TOKEN found.\n' +
        '              API calls will fail with 401/503 until you set one in ../.env or frontend/.env.local.\n'
    );
  } else if (authMode !== 'none') {
    // eslint-disable-next-line no-console
    console.log(`[palantir-ui] proxying /api -> ${target} as "${role}" role`);
  }

  const proxy = {
    '/api': {
      target,
      changeOrigin: true,
      configure: (p) => {
        p.on('proxyReq', (proxyReq) => {
          if (token) proxyReq.setHeader('Authorization', `Bearer ${token}`);
        });
      },
    },
    '/healthz': { target, changeOrigin: true },
  };

  return {
    plugins: [react()],
    define: {
      // Lets the UI hide write controls when it only holds a read token.
      __PALANTIR_UI_ROLE__: JSON.stringify(effectiveRole),
    },
    server: { port: Number(env.PALANTIR_UI_PORT) || 3000, proxy },
    preview: { port: Number(env.PALANTIR_UI_PORT) || 3000, proxy },
  };
});
