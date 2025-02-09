import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';

export default defineConfig({
  root: '/opt/irssh-panel/frontend',
  publicDir: 'public',
  plugins: [react()],
  build: {
    outDir: 'dist',
  },
  server: {
    open: true,
  }
});
