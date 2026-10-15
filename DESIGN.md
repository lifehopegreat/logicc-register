# Logicc Console — scope after GPT removal

Keep the existing Flask + HTML/CSS/JS stack and local stylesheet; this is a workflow removal, not a redesign.

- Mailbox management is the default view. Lists return readiness and local state only, never credentials.
- The registration view is a batch workbench: paste up to 100 mailboxes and up to 100 proxies, choose 1–32 concurrent workers, accept terms, launch. Credential rows are imported into the vault as part of the launch; bare addresses must already be imported.
- Proxies are assigned round-robin (one per account, cycling from the top when the pool is smaller) and pinned once before any account starts, so each account keeps a single gateway for the whole flow.
- A dispatcher keeps at most `workers` child processes in flight; each account still runs the unchanged single-account runner. Only one unfinished batch is allowed at a time.
- The batch log is a per-account-prefixed merge of the member logs, and the readout aggregates the batch; a drained batch with accounts still waiting on a human or a code reports that state instead of "completed".
- Optional encrypted CapMonster configuration enables one paid Turnstile task per run; resume re-queries a known task, never silently purchases another.
- Jobs, logs and results retain generic task infrastructure, without GPT retry, password, MFA, OAuth or export actions.
- Mailbox UI has four columns: email, source, status and masked Logicc platform password. No OTP or deletion controls in this view.
- A same-origin explicit JSON POST may reveal a confirmed same-account platform password, never the mailbox password. Clear its native dialog on close, navigation and backgrounding; do not persist it in the browser.
- The single-account launch form uses direct email/proxy input and a black live log panel above terms acceptance; the panel flexes to keep the launch button near the viewport bottom.
- The batch workbench keeps that black live log panel, adds a per-account progress table below it, and reports the assignment summary (accounts per gateway row) before launch.
- Launch readouts follow the currently displayed log job: completed/total in green, CapMonster balance in purple with a normal theme-text label. Numeric columns roll vertically and respect reduced motion. Balance reads are throttled to once per visible minute and never create solve tasks.
- Dialog close controls do not shrink or wrap; both the button and dialog use a clear theme-aware border.
- Keep semantic buttons, labels, focus outlines, desktop/mobile navigation, theme selection and existing reduced-motion rules.
- Settings retain mailbox, proxy and browser-host connection controls. Obsolete registration cost guards are removed.

Validation: Python tests, JavaScript syntax checks and local console smoke checks. Do not describe fixture-based email tests as real account verification.
