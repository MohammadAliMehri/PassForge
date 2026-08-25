# PassForge — Password Strength Analyzer & Generator

A privacy-first, frontend-only web app that analyzes password strength in real-time and generates cryptographically strong random passwords entirely in your browser.

## Features

- **Live password analysis** with strength score (0–100) and color-coded progress bar
- **Entropy estimation** in bits
- **Detailed feedback** with actionable suggestions
- **Checklist** for password requirements: length, character types, common passwords, sequences, repeats
- **Strong password generator** with adjustable length, character class toggles, and exclusion of ambiguous characters
- **Copy to clipboard** and "Use this password" to load into analyzer
- **100% offline** — no data is ever sent to any server

## Privacy & Security

- All analysis and generation happen locally in the browser
- No data is stored, logged, or transmitted
- Uses `crypto.getRandomValues()` for secure randomness
- No external dependencies or tracking

## Tech Stack

- HTML, CSS, vanilla JavaScript
- Dark mode, responsive design
- GitHub Pages ready

## Run Locally

Open `index.html` in a browser, or serve with any static server:

```bash
python -m http.server 8000
```

## License

MIT