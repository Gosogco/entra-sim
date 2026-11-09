import { PublicClientApplication } from '@azure/msal-browser'
import { MsalProvider } from '@azure/msal-react'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { App } from './App'
import { msalConfig } from './authConfig'
import './index.css'

const root = createRoot(document.getElementById('root')!)

// MSAL must be initialised, and the redirect response handled, before React renders.
async function start() {
  const msal = new PublicClientApplication(msalConfig)
  await msal.initialize()
  await msal.handleRedirectPromise()

  const accounts = msal.getAllAccounts()
  if (accounts.length > 0) {
    msal.setActiveAccount(accounts[0])
  }

  root.render(
    <StrictMode>
      <MsalProvider instance={msal}>
        <App />
      </MsalProvider>
    </StrictMode>,
  )
}

start().catch((error: unknown) => {
  root.render(
    <main>
      <h1>Startup failed</h1>
      <pre>{String(error)}</pre>
    </main>,
  )
})
