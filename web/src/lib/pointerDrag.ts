/** A pointer drag that survives whatever it passes over.
 *
 *  Every pane that can sit beside a divider may hold an <iframe> — each
 *  rendered-response view is one — and an iframe swallows the pointer events of
 *  the document it sits in: they are dispatched inside the iframe's own document
 *  and the parent never sees them. A drag listening on `document` therefore
 *  freezes the instant the pointer crosses into the neighbouring pane, and never
 *  sees its own pointerup either, so it never ends: the divider keeps tracking a
 *  pointer with no button held and `user-select` stays off for the session.
 *
 *  The fix is an explicit pointer capture. The capture target override is
 *  consulted before a hit test would forward the event into a nested browsing
 *  context, so the iframe is never in the path.
 *
 *  The capture is taken on the shield rather than on the handle, and that is the
 *  load-bearing part: a handle may unmount mid-drag — a divider rendered only
 *  while a row is selected does exactly that — and element removal does not
 *  reliably fire `lostpointercapture` across browsers, which would strand the
 *  drag. The shield is created and destroyed here, so it lives exactly as long as
 *  the gesture whatever React does to the tree.
 *
 *  The shield is not redundant with the capture. It is the only way to hold the
 *  resize cursor for the whole drag — `body.style.cursor` does not reach inside
 *  an iframe — and it keeps hover styles underneath from reacting.
 */

/** One drag at a time. `document.body.style.userSelect` is global, so a second
 *  concurrent drag's teardown would clear it out from under the first. */
let dragging = false

export type DragCursor = 'col-resize' | 'row-resize' | 'grabbing'

/** Begins a drag for `e`'s pointer. `onMove` is called at most once per frame
 *  with the latest position; `onEnd` runs once, on release, cancel, or window
 *  blur. Returns the same idempotent teardown, for a caller that must stop early.
 *  Returns null if a drag is already in flight. */
export function beginPointerDrag(
  e: React.PointerEvent,
  cursor: DragCursor,
  onMove: (ev: PointerEvent) => void,
  onEnd?: () => void,
): (() => void) | null {
  if (dragging) return null
  dragging = true
  e.preventDefault()

  const shield = document.createElement('div')
  shield.style.cssText = `position:fixed;inset:0;z-index:10001;cursor:${cursor}`
  document.body.appendChild(shield)
  document.body.style.userSelect = 'none'
  // A shield that outlived a throw here would cover the whole app with nothing
  // left to remove it. Without the capture the drag still works — the shield is
  // the hit-test target — it just ends when the pointer leaves the window.
  try {
    shield.setPointerCapture(e.pointerId)
  } catch {
    /* no capture; the shield carries the drag */
  }

  let frame = 0
  let pending: PointerEvent | null = null
  let done = false

  function apply() {
    frame = 0
    const ev = pending
    pending = null
    if (ev) onMove(ev)
  }

  function move(ev: PointerEvent) {
    if (ev.pointerId !== e.pointerId) return
    pending = ev
    if (!frame) frame = requestAnimationFrame(apply)
  }

  function end() {
    if (done) return
    done = true
    dragging = false
    if (frame) cancelAnimationFrame(frame)
    shield.removeEventListener('pointermove', move)
    shield.removeEventListener('pointerup', end)
    shield.removeEventListener('pointercancel', end)
    // An OS-level window switch mid-drag does not always produce a pointerup.
    window.removeEventListener('blur', end)
    shield.remove()
    document.body.style.userSelect = ''
    onEnd?.()
  }

  shield.addEventListener('pointermove', move)
  shield.addEventListener('pointerup', end)
  shield.addEventListener('pointercancel', end)
  window.addEventListener('blur', end)

  return end
}
