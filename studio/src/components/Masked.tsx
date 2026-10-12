import { useState } from 'react'

/// A secret, hidden until clicked.
///
/// The studio exists to show secrets, since they are fake and knowing them is the point of a
/// simulator. Masking still matters: screens get shared, and recorded in demos.
export function Masked({ value }: { value: string | undefined }) {
  const [shown, setShown] = useState(false)
  if (value === undefined) return <span className="muted">not in snapshot</span>
  return (
    <button
      type="button"
      className={`masked${shown ? ' shown' : ''}`}
      onClick={(event) => {
        // Rows expand on click, and revealing a secret should not also toggle the row.
        event.stopPropagation()
        setShown(!shown)
      }}
      title={shown ? 'Click to hide' : 'Click to reveal'}
      data-testid="masked"
    >
      {shown ? value : '••••••••'}
    </button>
  )
}
