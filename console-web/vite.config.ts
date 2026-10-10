/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The console serves the built files itself under a strict policy (default-src 'self'). The
// development server enforces the same policy, plus a nonce for the scripts and styles Vite injects
// for hot reload, so a component that needs inline script or style fails here first (section 13.1).
const DEV_NONCE = 'directory-console-dev';
const console_ = process.env.CONSOLE_URL ?? 'https://localhost:8443';

// The console's own production policy (console-server Server.headers), for `vite preview` of the build.
const PRODUCTION_CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

const apiProxy = {
  '/api': {
    target: console_,
    secure: false, // the console's own certificate is self-signed until one is installed
    configure: (proxy: { on: (e: 'proxyReq', f: (req: { setHeader: (k: string, v: string) => void; getHeader: (k: string) => unknown }) => void) => void }, _opts: unknown) => {
      // the console accepts a write only from its own origin: the page's host, as https
      proxy.on('proxyReq', (req) => req.setHeader('origin', `https://${String(req.getHeader('host'))}`));
    },
  },
};

export default defineConfig(({ command }) => ({
  plugins: [react()],
  html: command === 'serve' ? { cspNonce: DEV_NONCE } : undefined,
  build: {
    outDir: 'dist',
    // never data: URIs: the policy has no img-src or font-src exception for them
    assetsInlineLimit: 0,
    sourcemap: false,
    // one bundle, almost all React and PatternFly: ~190 kB gzipped and cached for a year by the console
    chunkSizeWarningLimit: 800,
  },
  server: {
    port: 5173,
    strictPort: true,
    headers: {
      'Content-Security-Policy': [
        "default-src 'self'",
        `script-src 'self' 'nonce-${DEV_NONCE}'`,
        `style-src 'self' 'nonce-${DEV_NONCE}'`,
        "connect-src 'self' ws://localhost:5173",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
      ].join('; '),
    },
    proxy: apiProxy,
  },
  preview: {
    // the built files under exactly the policy the console serves them with
    port: 4173,
    strictPort: true,
    headers: { 'Content-Security-Policy': PRODUCTION_CSP },
    proxy: apiProxy,
  },
  test: {
    environment: 'node',
  },
}));
