import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@core': resolve(__dirname, 'src/core'),
      '@api': resolve(__dirname, 'src/api'),
      '@db': resolve(__dirname, 'src/db'),
      '@services': resolve(__dirname, 'src/services'),
      '@utils': resolve(__dirname, 'src/utils'),
      '@types': resolve(__dirname, 'src/types'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/__tests__/**/*.test.ts', 'tests/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/__tests__/**',
        'src/types/**',
        'src/db/migrations/**',
        'src/db/seeds/**',
        'src/index.ts',
        'src/api/**',
        'src/db/client.ts',
        'src/db/schema/**',
        'src/utils/config.ts',
        'src/utils/errors.ts',
        'src/utils/validators.ts',
      ],
      thresholds: {
        statements: 80,
        branches: 75,
        functions: 80,
        lines: 80,
      },
    },
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
