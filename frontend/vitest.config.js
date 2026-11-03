import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// Конфиг тестов фронтенда (stage-13). Запуск: docker compose --profile tests run --rm frontend-tests
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.js',
  },
});
