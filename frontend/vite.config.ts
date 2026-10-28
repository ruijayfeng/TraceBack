import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import tailwindcss from '@tailwindcss/vite';

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [tailwindcss()],
  resolve: { alias: { '@': path.resolve(root, 'src') } },
  server: { proxy: { '/api': { target: process.env.TRACEBACK_API_URL || 'http://127.0.0.1:8000', changeOrigin: false } } },
  test: { environment: 'jsdom', setupFiles: ['./src/test/setup.ts'], include: ['src/**/*.test.ts', 'src/**/*.test.tsx'] },
});
