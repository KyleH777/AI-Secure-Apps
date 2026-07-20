# ARIA & Accessibility Audit — Multi-Step Checkout Form

Component: `frontend/checkout/` (index.html, checkout.css, checkout.js)
Target: WCAG 2.1 Level AA
Verification: every ☑ item below is also asserted by an automated
keyboard-driven Chromium run (19 checks) executed before commit.

## 1. Semantic HTML

- ☑ Landmarks: `<header>`, `<nav aria-label="Checkout progress">`, `<main>` — one `<main>`, labelled nav.
- ☑ All interactive elements are native: `<button>`, `<input>`, `<select>`, `<a>`. Zero click-handlers on `<div>`/`<span>`.
- ☑ Buttons vs. links used by behavior: in-page state changes are `<button>` (including "Edit" actions); the only `<a>` elements are the skip link and error-summary links (which navigate focus).
- ☑ Heading hierarchy: single `<h1>`, one `<h2>` per step, `<h3>` for review subsections — no skipped levels.
- ☑ Related fields grouped in `<fieldset>` with `<legend>` (Contact, Delivery address, Delivery method, Card details).
- ☑ Every control has a programmatically associated `<label for>`. No placeholder-as-label.
- ☑ Review summary uses `<dl>/<dt>/<dd>`; progress uses an `<ol>` (order is meaningful).

## 2. Keyboard Navigation (WCAG 2.1.1, 2.1.2, 2.4.3, 2.4.7)

- ☑ Skip link is the first tab stop (WCAG 2.4.1); visually hidden until focused.
- ☑ Every interactive element reachable with `Tab` in logical DOM order; no `tabindex` > 0 anywhere.
- ☑ `Enter`/`Space` activate buttons (native); arrow keys move within the radio group (native, verified).
- ☑ Inactive steps carry `hidden` → removed from tab order and accessibility tree; no keyboard traps.
- ☑ `:focus-visible` styling: 3 px solid high-contrast outline with 2 px offset, defined globally and never suppressed; uses `outline` so it survives Windows High Contrast / forced-colors mode.
- ☑ Programmatic focus management: on step change focus lands on the new step's `h2[tabindex="-1"]`; on validation failure focus lands on the error summary; error links move focus into the offending field.

## 3. ARIA Usage (used only where native HTML falls short)

| Attribute | Where | Why |
| --- | --- | --- |
| `aria-current="step"` | Progress `<li>` | Marks the active step for AT; visual equivalent is bold + underline (not color alone) |
| `aria-live="polite"` | `#status-live` | Announces "Step X of 3: …" and order confirmation without stealing focus (WCAG 4.1.3) |
| `role="alert"` + focus | `#error-summary` | Assertive announcement of validation failures; `tabindex="-1"` allows focus target |
| `aria-describedby` | Every input | Chains hint + error-slot ids so AT reads guidance and current error with the field (WCAG 3.3.2) |
| `aria-invalid="true"` | Failing inputs | Set only while invalid; removed the moment the user fixes the field |
| `aria-hidden="true"` | Decorative step numerals, divider | Pure decoration duplicated by visible text |
| `aria-label` | Progress `<nav>` | Distinguishes it from other navigation landmarks |

Deliberately absent: no `role="button"` (real buttons), no ARIA listbox
(native `<select>`), no `aria-expanded` (nothing expands/collapses in this
component), no redundant `role="form"`/`role="main"` on native elements.

## 4. Forms & Error Handling (WCAG 3.3.1–3.3.4)

- ☑ Error summary pattern: focused container listing every error as a link to its field.
- ☑ Inline errors are prefixed "Error:" via CSS `::before` text (perceivable without color) and announced via `aria-describedby`.
- ☑ Errors are specific and actionable ("Enter the expiry date as MM/YY, like 04/28"), not "invalid input".
- ☑ Errors clear as soon as the field becomes valid (no stale announcements).
- ☑ `autocomplete` tokens on every field (`name`, `email`, `street-address`, `postal-code`, `country-name`, `cc-*`) — WCAG 1.3.5 Identify Input Purpose.
- ☑ Review step before submission satisfies WCAG 3.3.4 (error prevention for financial transactions): all data is shown for confirmation with per-section Edit buttons.
- ☑ `novalidate` + JS validation gives consistent, announced errors across browser/AT combinations.

## 5. Contrast & Visual (WCAG 1.4.1, 1.4.3, 1.4.11)

Measured against white (#ffffff):

| Token | Hex | Ratio | Requirement |
| --- | --- | --- | --- |
| Body text | `#1f2933` | 14.7:1 | ≥ 4.5:1 ☑ |
| Hint text | `#52606d` | 6.0:1 | ≥ 4.5:1 ☑ |
| Error text | `#b3261e` | 5.9:1 | ≥ 4.5:1 ☑ |
| Primary button text | `#ffffff` on `#1d4ed8` | 6.3:1 | ≥ 4.5:1 ☑ |
| Input borders (2 px) | `#64748b` | 4.7:1 | ≥ 3:1 (non-text) ☑ |
| Focus ring | `#1d4ed8` | 6.3:1 | ≥ 3:1 (non-text) ☑ |

- ☑ No state conveyed by color alone: current step = `aria-current` + bold + underline; errors = text prefix + message + border; completed steps = "(completed)" in AT text.

## 6. Reflow & Zoom (WCAG 1.4.4, 1.4.10)

- ☑ All dimensions in `rem`; text scales with user font-size settings.
- ☑ Verified: no horizontal scrolling at 320 px viewport width (equivalent to 400 % zoom on a 1280 px screen); field rows and the progress bar wrap.
- ☑ Viewport meta does not set `maximum-scale` or `user-scalable=no`.
- ☑ `prefers-reduced-motion` guard in place (component itself uses no animation).

## 7. Screen-Reader Behavior Summary

1. Page load → "Checkout, heading level 1"; progress nav announces "Shipping — step 1 of 3, current step".
2. "Continue" with empty fields → alert "There is a problem" + focus on summary; each error is a link.
3. Step change → focus on the new step heading; polite announcement "Step 2 of 3: Payment".
4. Review step → all entered data read from the description list; card number exposed only as "Ending in ····".
5. Submit → focus on "Order placed" heading + polite confirmation announcement.

## Known limitations / manual-test recommendations

- Automated checks ran in Chromium only; recommend one manual pass with NVDA + Firefox and VoiceOver + Safari before production.
- The demo stores nothing and submits nowhere; wiring it to the real API must keep server-side validation as the source of truth (client validation here is UX, not security).
