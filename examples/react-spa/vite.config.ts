import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // Fixed, because the redirect URI is registered on the application and must match
    // exactly. Entra rejects a redirect URI it does not know, and so does the simulator.
    port: 5173,
    strictPort: true,
  },
  preview: { port: 5173, strictPort: true },
})
