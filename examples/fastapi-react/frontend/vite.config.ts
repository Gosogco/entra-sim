import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // The .env that Terraform writes is shared with the backend and the daemons.
  envDir: '..',
  server: {
    // Fixed, because the redirect URI is registered on the application and must match
    // exactly. 5174 rather than 5173, so this runs beside the React example.
    port: 5174,
    strictPort: true,
    // The backend is reached through the dev server, so it is same-origin and needs no CORS.
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
})
