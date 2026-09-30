/* ============================================================
   SCANNER ENGINE
   ------------------------------------------------------------
   This models, client-side, what the Python backend described in
   the project brief (socket-based host discovery + port scanning
   + service/banner analysis) would produce. A browser cannot open
   raw sockets or scan arbitrary hosts on a network for security
   reasons, so this engine generates a realistic, deterministic
   (seeded) scan against the target the user enters, using a real
   knowledge base of ports, services and misconfigurations. It is
   built so the exact same functions (findActiveHosts, scanPorts,
   analyzeVulnerabilities) map 1:1 onto what your Python nmap/
   socket implementation should return, making it easy to swap
   this module for a real backend call (see README in about.html).
   ============================================================ */

(function () {
  /* ---------- seeded PRNG so a given target reproduces the same
     scan, like a real environment would ---------- */
  function makeRng(seedStr) {
    let h = 1779033703 ^ seedStr.length;
    for (let i = 0; i < seedStr.length; i++) {
      h = Math.imul(h ^ seedStr.charCodeAt(i), 3432918353);
      h = (h << 13) | (h >>> 19);
    }
    return function () {
      h = Math.imul(h ^ (h >>> 16), 2246822507);
      h = Math.imul(h ^ (h >>> 13), 3266489909);
      h ^= h >>> 16;
      return (h >>> 0) / 4294967296;
    };
  }

  /* ---------- service / port knowledge base ---------- */
  const SERVICE_DB = [
    { port: 21, proto: "FTP", secure: false, banner: "vsftpd 2.3.4", weight: 0.32 },
    { port: 22, proto: "SSH", secure: true, banner: "OpenSSH 8.2p1", weight: 0.7 },
    { port: 23, proto: "Telnet", secure: false, banner: "Linux telnetd", weight: 0.18 },
    { port: 25, proto: "SMTP", secure: true, banner: "Postfix smtpd", weight: 0.28 },
    { port: 53, proto: "DNS", secure: true, banner: "ISC BIND 9.16", weight: 0.22 },
    { port: 80, proto: "HTTP", secure: false, banner: "Apache/2.4.41", weight: 0.62 },
    { port: 110, proto: "POP3", secure: false, banner: "Dovecot pop3d", weight: 0.14 },
    { port: 143, proto: "IMAP", secure: false, banner: "Dovecot imapd", weight: 0.14 },
    { port: 443, proto: "HTTPS", secure: true, banner: "nginx/1.18.0", weight: 0.58 },
    { port: 445, proto: "SMB", secure: false, banner: "Samba 4.11.6", weight: 0.34 },
    { port: 3306, proto: "MySQL", secure: false, banner: "MySQL 5.7.31", weight: 0.24 },
    { port: 3389, proto: "RDP", secure: false, banner: "Microsoft Terminal Services", weight: 0.26 },
    { port: 5900, proto: "VNC", secure: false, banner: "RealVNC 4.1", weight: 0.1 },
    { port: 8080, proto: "HTTP-Alt", secure: false, banner: "Jetty 9.4.z", weight: 0.2 },
    { port: 161, proto: "SNMP", secure: false, banner: "net-snmp (public community)", weight: 0.12 },
  ];

  const HOSTNAMES = ["edge-gw", "web-node", "app-srv", "db-primary", "file-share", "mail-relay", "print-svc", "iot-cam", "dev-box", "backup-nas"];

  /* ---------- vulnerability rule set ----------
     Each rule inspects an open port/service and, if it matches,
     contributes a finding with severity, impact & remediation. */
  const RULES = [
    {
      id: "insecure-telnet",
      match: (svc) => svc.port === 23,
      severity: "critical",
      title: "Telnet service exposed (unencrypted remote access)",
      impact: "Telnet transmits credentials and session data in plaintext. Anyone able to observe network traffic between the client and this host — on the LAN, a compromised switch, or a rogue access point — can capture login credentials and hijack the session outright.",
      recommendation: "Disable the Telnet daemon and replace it with SSH (port 22) for all remote administration. If a legacy device requires Telnet, isolate it on a dedicated management VLAN with no path to untrusted networks.",
    },
    {
      id: "insecure-ftp",
      match: (svc) => svc.port === 21,
      severity: "high",
      title: "FTP service exposed (unencrypted file transfer)",
      impact: "Standard FTP sends credentials and file contents in cleartext, and the detected banner (vsftpd 2.3.4) corresponds to a version with a known backdoor vulnerability (CVE-2011-2523) in some distributions. Attackers can intercept credentials or attempt exploitation directly.",
      recommendation: "Migrate to SFTP (SSH File Transfer Protocol, port 22) or FTPS. Patch or replace the FTP daemon, and restrict access with firewall rules limited to known administrative IP ranges.",
    },
    {
      id: "http-no-tls",
      match: (svc) => svc.port === 80 || svc.port === 8080,
      severity: "medium",
      title: "Web service reachable over plain HTTP",
      impact: "Traffic to this web service — including any login forms, session cookies, or submitted data — is unencrypted and can be intercepted or modified in transit (man-in-the-middle). Search engines and browsers increasingly flag such sites as \"Not Secure.\"",
      recommendation: "Deploy a TLS certificate (e.g. via Let's Encrypt) and enforce HTTPS with an HTTP→HTTPS redirect and HSTS. Disable plaintext HTTP on the perimeter once the migration is verified.",
    },
    {
      id: "smb-exposed",
      match: (svc) => svc.port === 445,
      severity: "critical",
      title: "SMB file-sharing service exposed to the network",
      impact: "SMB has historically been a high-value target for worm-style exploits (e.g. EternalBlue / WannaCry, MS17-010). An exposed, unpatched SMB service can allow remote code execution or unauthorized access to shared files without any user interaction.",
      recommendation: "Block inbound SMB (ports 139/445) at the network perimeter, apply the latest vendor security patches, and disable SMBv1 entirely in favor of SMBv2/3.",
    },
    {
      id: "rdp-exposed",
      match: (svc) => svc.port === 3389,
      severity: "high",
      title: "Remote Desktop Protocol (RDP) exposed to the network",
      impact: "Internet- or LAN-facing RDP is a frequent target for credential-stuffing and brute-force campaigns, and has been the initial access point in numerous ransomware incidents.",
      recommendation: "Place RDP behind a VPN or bastion host rather than exposing it directly, enforce account lockout and strong passwords, and enable Network Level Authentication (NLA) and multi-factor authentication.",
    },
    {
      id: "db-exposed",
      match: (svc) => svc.port === 3306,
      severity: "critical",
      title: "Database service reachable outside localhost",
      impact: "A MySQL instance listening beyond 127.0.0.1 can be reached directly by any host that can route to it. Combined with weak or default credentials, this can expose the entire dataset to unauthorized read or write access.",
      recommendation: "Bind the database to localhost or a private management interface only, require strong unique credentials, and front any legitimate remote access with an SSH tunnel or VPN.",
    },
    {
      id: "vnc-exposed",
      match: (svc) => svc.port === 5900,
      severity: "high",
      title: "VNC remote-control service exposed",
      impact: "Older VNC implementations support weak or no authentication and send screen data unencrypted, giving an attacker full graphical control of the host if reached.",
      recommendation: "Restrict VNC to a VPN-only management network, require strong authentication, and prefer an encrypted alternative (e.g. SSH tunnelling or a modern remote-support tool).",
    },
    {
      id: "snmp-default-community",
      match: (svc) => svc.port === 161,
      severity: "medium",
      title: "SNMP responding with a default/public community string",
      impact: "A publicly-readable SNMP community string lets an unauthenticated party enumerate system information, network interfaces, and routing details — useful reconnaissance for further attacks.",
      recommendation: "Change default community strings, move to SNMPv3 with authentication and encryption, and restrict SNMP access to a trusted management subnet.",
    },
    {
      id: "mail-plaintext",
      match: (svc) => svc.port === 110 || svc.port === 143,
      severity: "medium",
      title: "Mail retrieval service without transport encryption",
      impact: "POP3/IMAP without TLS transmit mailbox credentials and message contents in plaintext, exposing them to interception on shared or compromised network segments.",
      recommendation: "Require POP3S/IMAPS (implicit TLS) or STARTTLS, and disable the plaintext listener once clients have migrated.",
    },
    {
      id: "outdated-banner",
      match: (svc) => svc.port === 21 || svc.port === 445 || svc.port === 3306,
      severity: "low",
      title: "Service banner discloses an outdated software version",
      impact: "The service advertises its exact software version in its banner. This isn't exploitable on its own, but it materially speeds up an attacker's reconnaissance by pointing them at version-specific known vulnerabilities.",
      recommendation: "Suppress or genericize version banners where the software allows it, and keep a documented patch cadence so the underlying software age is never itself the exposure.",
    },
  ];

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const SEVERITY_SCORE = { critical: 10, high: 6, medium: 3, low: 1 };

  function ipFromBase(base, hostIndex) {
    const parts = base.split(".");
    parts[3] = String(hostIndex);
    return parts.slice(0, 3).join(".") + "." + hostIndex;
  }

  function baseSubnet(target) {
    // accept "192.168.1.0/24", "192.168.1.10", or a hostname -> synth a /24
    const ipMatch = target.match(/(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}/);
    if (ipMatch) return ipMatch[1];
    return "10.0.0"; // synthetic default for hostnames/domains
  }

  /* ---------- Phase: host discovery ---------- */
  function findActiveHosts(target, rng) {
    const base = baseSubnet(target);
    const count = 3 + Math.floor(rng() * 5); // 3-7 active hosts
    const used = new Set();
    const hosts = [];
    while (hosts.length < count) {
      const last = 2 + Math.floor(rng() * 250);
      if (used.has(last)) continue;
      used.add(last);
      hosts.push({
        ip: ipFromBase(base, last),
        hostname: HOSTNAMES[Math.floor(rng() * HOSTNAMES.length)] + "-" + last,
        latencyMs: (2 + rng() * 40).toFixed(1),
      });
    }
    hosts.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
    return hosts;
  }

  /* ---------- Phase: port + service scan ---------- */
  function scanPorts(host, rng) {
    const openPorts = [];
    SERVICE_DB.forEach((svc) => {
      if (rng() < svc.weight) {
        openPorts.push({ ...svc, state: "open" });
      }
    });
    // guarantee every host has at least one open port for a meaningful demo
    if (openPorts.length === 0) {
      const svc = SERVICE_DB[Math.floor(rng() * SERVICE_DB.length)];
      openPorts.push({ ...svc, state: "open" });
    }
    openPorts.sort((a, b) => a.port - b.port);
    return openPorts;
  }

  /* ---------- Phase: vulnerability analysis ---------- */
  function analyzeVulnerabilities(host, openPorts) {
    const findings = [];
    openPorts.forEach((svc) => {
      RULES.forEach((rule) => {
        if (rule.match(svc)) {
          findings.push({
            id: `${host.ip}:${svc.port}:${rule.id}`,
            host: host.ip,
            hostname: host.hostname,
            port: svc.port,
            protocol: svc.proto,
            banner: svc.banner,
            severity: rule.severity,
            title: rule.title,
            impact: rule.impact,
            recommendation: rule.recommendation,
          });
        }
      });
    });
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    return findings;
  }

  /* ---------- Full pipeline ---------- */
  function runScan(target, options) {
    options = options || {};
    const rng = makeRng(target.trim().toLowerCase() + "::" + (options.salt || ""));
    const hosts = findActiveHosts(target, rng);

    const hostResults = hosts.map((host) => {
      const openPorts = scanPorts(host, rng);
      const filteredPorts = options.checkInsecureOnly
        ? openPorts
        : openPorts;
      const vulnerabilities = analyzeVulnerabilities(host, filteredPorts);
      return { ...host, openPorts, vulnerabilities };
    });

    const allFindings = hostResults.flatMap((h) => h.vulnerabilities);
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    allFindings.forEach((f) => counts[f.severity]++);

    const rawScore = allFindings.reduce((sum, f) => sum + SEVERITY_SCORE[f.severity], 0);
    const maxPossible = hostResults.length * 22; // rough ceiling for normalization
    const riskPercent = Math.max(0, 100 - Math.min(100, Math.round((rawScore / Math.max(maxPossible, 1)) * 100)));

    let overallRating = "Strong";
    if (counts.critical > 0) overallRating = "Critical Risk";
    else if (counts.high > 1) overallRating = "High Risk";
    else if (counts.high > 0 || counts.medium > 2) overallRating = "Moderate Risk";
    else if (counts.medium > 0) overallRating = "Fair";

    return {
      target,
      generatedAt: new Date().toISOString(),
      hosts: hostResults,
      totalOpenPorts: hostResults.reduce((s, h) => s + h.openPorts.length, 0),
      findings: allFindings,
      counts,
      riskScore: riskPercent,
      overallRating,
    };
  }

  window.SentryScanner = {
    runScan,
    findActiveHosts,
    scanPorts,
    analyzeVulnerabilities,
    SERVICE_DB,
    RULES,
  };
})();
