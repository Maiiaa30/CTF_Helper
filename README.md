# CTF Helper

A fast, searchable command and reference hub for CTF challenges and penetration
testing. Single-page, fully static — no build step, no backend, no tracking. Built
to live on a second monitor and keep your whole workflow one keystroke away.

**Live:** https://ctf.arentim.com

## Why

During an engagement you don't want to dig through scattered notes, cheat sheets and
browser tabs. CTF Helper puts the commands you actually use — recon, web, privesc,
Active Directory, shells, pwn, crypto — behind a single search box, with a scratchpad
for the box you're working and one-click copy for everything.

## Features

- **Live search** across every command, description and tag (`/` or `Ctrl`/`Cmd`+`K`)
- **Active Target panel** — host, open ports, current phase and notes, saved per browser
- **Quick Access** — pin any command for instant reuse
- **One-click copy** with confirmation on every command
- **Reverse-shell generator** — set `LHOST`/`LPORT`, get bash, python, nc, php,
  powershell and perl variants plus matching listeners
- **Category tabs** with collapsible groups that remember their state
- **Fully offline** — open the file, no network required

## Content

Curated, working commands organised into categories:

| Category | Covers |
|---|---|
| Recon / Enumeration | nmap, service enum, DNS, SMB, web discovery |
| Web Exploitation | SQLi, XSS, LFI/RFI, SSTI, upload bypass, fuzzing |
| Linux Privesc | SUID, sudo, cron, capabilities, GTFOBins paths |
| Windows Privesc | tokens, services, registry, DLL hijack, loot |
| Active Directory | enum, Kerberos, BloodHound, lateral movement |
| Reverse Shells & Transfer | shell generator, upgrades, file transfer |
| Binary Exploitation | gdb/pwndbg, ROP, format string, patterns |
| Crypto / Steg / Forensics | hashes, ciphers, stego, memory, packet analysis |
| Stuck? Start Here | decision helper when a box stalls |
| Useful Links | reference sites and payload repos |

## Usage

Open `index.html` directly, or serve the directory:

```bash
python3 -m http.server 8000
```

All state (target info, pins, open/closed sections, active tab) persists in
`localStorage` — nothing leaves the browser.

### Keyboard shortcuts

| Key | Action |
|---|---|
| `/` or `Ctrl`/`Cmd`+`K` | Focus search |
| `Esc` | Clear search |

## Deployment

Static files at repo root — drop them on any static host (Cloudflare Pages/Workers,
GitHub Pages, Netlify, S3). No build command, output directory is the repo root.

Current production deploy (Cloudflare):

```bash
npx wrangler@latest pages deploy . --project-name ctf-helper
```

## Project structure

```
index.html    markup / app shell
styles.css    dark theme and layout
data.js       command & reference content
app.js        rendering, search, pin, copy, persistence
```

## Tech

Vanilla HTML, CSS and JavaScript. No dependencies, no framework, no build tooling.
All content is data-driven from a single array in `data.js` — add a category or a
command by editing that file.

## License

MIT
