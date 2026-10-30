import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    // 真实 antd 表格/弹窗渲染较重,避免小规格 CI 并行争用 CPU 导致误超时。
    maxWorkers: 2,
    testTimeout: 15_000,
  },
});
