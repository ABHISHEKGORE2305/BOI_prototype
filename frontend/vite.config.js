import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // React is shared by every chunk and must not be filed under a lazy
        // vendor chunk, or the entry would have to download that chunk too
        manualChunks(id) {
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return 'react';
          if (/[\\/]node_modules[\\/](react-markdown|remark-[^\\/]+|micromark[^\\/]*|mdast-[^\\/]+)[\\/]/.test(id)) return 'markdown';
          return undefined;
        },
      },
    },
  },
  server: {
    // Same-origin API calls in development; nginx does this in Docker
    proxy: {
      '/api': process.env.VITE_PROXY_TARGET || 'http://127.0.0.1:8000',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.js',
    globals: true,
  },
})
