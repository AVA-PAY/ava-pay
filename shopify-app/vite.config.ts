import { reactRouter } from '@react-router/dev/vite';
import { defineConfig } from 'vite';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  server: {
    port: Number(process.env.PORT ?? 3001),
    fs: { allow: ['app', 'node_modules'] },
    // `shopify app dev` serves the app through a fresh *.trycloudflare.com
    // tunnel each run; the leading dot allows any subdomain of the suffix.
    allowedHosts: ['.trycloudflare.com'],
  },
  plugins: [reactRouter(), tsconfigPaths()],
  build: {
    assetsInlineLimit: 0,
  },
});
