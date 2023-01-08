import { defineConfig, loadEnv } from 'vite';
import solidPlugin from 'vite-plugin-solid';

export default defineConfig(({ mode }) => ({
  plugins: [solidPlugin(), htmlPlugin(loadEnv(mode, '.')),],
  server: {
    port: 3000,
  },
  build: {
    target: 'esnext',
  },
}));

function htmlPlugin(env: ReturnType<typeof loadEnv>) {
  return {
    name: 'html-transform',
    transformIndexHtml: {
      enforce: 'pre' as const,
      transform: (html: string): string =>
        html.replace(/%(.*?)%/g, (match, p1) =>
          env[p1] ?? match
        ),
    }
  }
}
