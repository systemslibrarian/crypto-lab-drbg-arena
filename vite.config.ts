import { defineConfig } from 'vitest/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: '/crypto-lab-drbg-arena/',
  build: {
    outDir: 'dist',
  },
  plugins: [tailwindcss()],
  test: {
    include: ['src/**/*.test.ts'],
  },
});
