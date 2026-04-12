import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: '/crypto-lab-drbg-arena/',
  build: {
    outDir: 'dist',
  },
  plugins: [tailwindcss()],
});
