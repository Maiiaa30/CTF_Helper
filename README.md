# CTF Helper

A fast, searchable, dark-themed command and reference hub for CTF challenges and
penetration testing. Single-page, fully static, no build step, no backend.

## Features

- Live fuzzy search across every command, description and tag
- Persistent "Active Target" panel (host, ports, phase, notes) stored in your browser
- Pin / favourite any command into a Quick Access tray
- One-click copy with confirmation
- Collapsible sections that remember their state
- Interactive reverse-shell generator
- Keyboard shortcut (`/`) to jump to search
- Works entirely offline

## Usage

Open `index.html` in a browser, or serve the directory statically:

```bash
python3 -m http.server 8000
```

All state (target info, pins, open/closed sections) is saved to `localStorage`.

## Structure

```
index.html    markup / app shell
styles.css    dark theme
data.js       command & reference content
app.js        rendering, search, pin, copy, persistence
```
