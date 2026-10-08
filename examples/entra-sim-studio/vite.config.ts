import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // Fixed, and one above the React example's 5173, so both can run side by side while you
    // watch the directory change underneath the other one.
    port: 5174,
    strictPort: true,
  },
  preview: { port: 5174, strictPort: true },
})
