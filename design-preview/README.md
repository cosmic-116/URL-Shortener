# Snip design preview

A standalone visual concept, also available as the optional **Alternate look · Demo** at `/design/demo/` in Flask. The classic design remains the default. Demo forms use sample data; authentication, analytics, balances, and shortening never call the live service.

## Run

On Windows, double-click **Start Preview.cmd** to start the sample and open your browser.

Or, from the repository folder:

```powershell
python design-preview/server.py
```

Open **http://127.0.0.1:4173**. Stop the server with Ctrl+C.

You can also open `index.html` directly. There is no build step or package installation.

Use **Design preview** in the bottom corner to explore every screen, including empty, error, email, and guest-limit states. The forms, link tools, filters, settings, dialogs, and downloads work with sample data. They never call the live service, send email, or alter the real database. Sample links are illustrative. The QR represents `https://snip-it.me`, not newly entered destinations.

The main flows are homepage → short-link result, login → dashboard, signup → verification → key reveal, password recovery, dashboard link management, QR Studio, account settings, and ad transit. Settings and links reset on refresh.

## Design direction

Warm paper and deep ink; an acid-yellow signature; generous editorial typography; fine rules instead of floating glass cards; compact product controls; purposeful motion. The public site and application use the same type, spacing, shapes, and icon language, with a different layout for each job.

## Alternate demo features

- Light/dark mode, following the system by default and remembering your choice on this device.
- Animated scissors cut a sample URL before its result appears. Reduced motion skips the effect. The same effect runs after successful guest shortening on the classic homepage.
- QR Studio: module and finder shapes, colors and gradients, caption and print-card frames, local logo upload, saved styles, and 600/1200/2400px PNG or SVG exports. A four-module quiet zone is preserved. Low-contrast exports are blocked. All demo QR codes encode `https://snip-it.me`.
- Logos stay in memory in the browser and are not uploaded or included in saved styles. Scan exported designs before sharing.
- Hosted files are allowlisted; server source and backups are not served. The demo is excluded from indexing.

Use **Back to classic** to leave the demo. No current account, link, or analytics data is loaded into it.
