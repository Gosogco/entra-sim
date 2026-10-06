import { PublicClientApplication } from '@azure/msal-browser'
import { MsalProvider } from '@azure/msal-react'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { App } from './App'
import { msalConfig } from './authConfig'
import './index.css'

const root = createRoot(document.getElementById('root')!)

// MSAL v3 and later must be initialised before any other call, and the redirect response must
// be handled before React renders. Doing it here keeps that ordering explicit rather than
// relying on a component's effect firing early enough.
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
  // A configuration fault must be visible on the page. A blank screen with a console error is
  // the hardest thing to diagnose, especially from a headless test.
  root.render(
    <main>
      <h1>Startup failed</h1>
      <pre data-testid="startup-error">{String(error)}</pre>
    </main>,
  )
})
