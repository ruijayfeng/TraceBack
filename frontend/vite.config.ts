import { defineConfig } from 'vitest/config';
export default defineConfig({
  server: { proxy: { '/api': { target: process.env.TRACEBACK_API_URL || 'http://127.0.0.1:8000', changeOrigin: false } } },
  test: { environment: 'jsdom', setupFiles: ['./src/test/setup.ts'], include: ['src/**/*.test.ts', 'src/**/*.test.tsx'] },
});
