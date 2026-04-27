// CompTIA Security+ SY0-701 — OSI Model: Layers, Attacks, and Controls
// Mnemonic (bottom → top, L1–L7): "Please Do Not Throw Sausage Pizza Away"
// Mnemonic (top → bottom, L7–L1): "All People Seem To Need Data Processing"

const OSI_CATEGORY_OPTIONS=[
  {value:"0",label:"The 7 OSI Layers"},
  {value:"1",label:"OSI Attacks & Exploits"},
  {value:"2",label:"OSI Security Controls"},
];

const OSI_CARDS=[

// ══════════════════════════════════════════════════════════════
// cat:0  THE 7 OSI LAYERS
// acr = "Layer X"  |  full = "Name Layer"  (returned as quiz answer)
// ══════════════════════════════════════════════════════════════

{cat:0,catName:"OSI Layers",acr:"Layer 1",full:"Physical Layer",
def:`Definition:
The Physical layer transmits raw bits as electrical signals, light pulses, or radio waves across a physical medium. It defines cables, connectors, voltage levels, pin layouts, and signaling standards. Hardware: NICs, hubs, repeaters, cables, fiber, wireless transceivers.

Clue:
If the question involves physical hardware, cables, bit transmission, or raw signals — it is Layer 1. No addressing, no error correction, just signal transmission.

Example:
A network tap is clipped onto a fiber optic cable between two switches to capture every bit transmitted — an attacker or analyst reading raw light pulses is operating at Layer 1.

Contrast:
Layer 2 (Data Link) builds on Layer 1 by adding MAC addressing and grouping bits into frames. Layer 1 has zero awareness of addresses — it only transmits signals.`,
trick:"Layer 1 = Physical. Mnemonic: 'Please' (P=Physical). Think cables, hubs, voltages — anything you can trip over."},

{cat:0,catName:"OSI Layers",acr:"Layer 2",full:"Data Link Layer",
def:`Definition:
The Data Link layer frames raw bits into structured units called frames, adds MAC (Media Access Control) addresses for local delivery, and detects transmission errors using CRC. Devices: switches, bridges, wireless access points. Sub-layers: LLC (Logical Link Control) and MAC. Key protocols: Ethernet, 802.11 Wi-Fi, ARP, PPP.

Clue:
Look for MAC addresses, Ethernet frames, switches, ARP, VLANs, or local network segment communication. Layer 2 handles hop-to-hop delivery on the same network segment.

Example:
A switch receives an Ethernet frame, reads the destination MAC address ff:d8:a2:11:05:c3, looks it up in its CAM table, and forwards the frame out only the correct port — this entire process is Layer 2.

Contrast:
Layer 3 (Network) handles IP-based routing between different networks. Layer 2 only communicates within a single network segment using MAC addresses, not IP addresses.`,
trick:"Layer 2 = Data Link. 'Do' in mnemonic. MAC addresses, switches, frames — local delivery only. ARP lives here."},

{cat:0,catName:"OSI Layers",acr:"Layer 3",full:"Network Layer",
def:`Definition:
The Network layer handles logical IP addressing and routing — determining the best path for packets to travel across multiple networks from source to destination. Devices: routers, Layer 3 switches. Protocols: IP (IPv4/IPv6), ICMP, OSPF, BGP, RIP. PDU: Packet.

Clue:
Look for IP addresses, routing tables, routers, subnets, or inter-network communication. If traffic crosses network boundaries (different IP ranges), Layer 3 is involved.

Example:
A router receives a packet destined for 10.20.5.14, consults its routing table, and forwards the packet out the correct interface toward the destination subnet — this is Layer 3 routing.

Contrast:
Layer 2 uses MAC addresses for same-segment delivery. Layer 3 uses IP addresses for cross-network routing. Firewalls filtering by IP address/subnet operate at Layer 3.`,
trick:"Layer 3 = Network. 'Not' in mnemonic. IP addresses, routers, routing tables — think GPS navigation across the internet."},

{cat:0,catName:"OSI Layers",acr:"Layer 4",full:"Transport Layer",
def:`Definition:
The Transport layer provides end-to-end communication between processes, handling segmentation, reassembly, flow control, and error recovery. TCP: connection-oriented, reliable, three-way handshake, guaranteed delivery. UDP: connectionless, fast, no guarantee. Uses port numbers to identify specific applications. PDU: Segment (TCP) / Datagram (UDP).

Clue:
Look for port numbers, TCP/UDP, connection state, reliability, or flow control. Stateful firewalls and port-based rules operate at Layer 4.

Example:
A web browser opens TCP port 443 with a three-way handshake (SYN → SYN-ACK → ACK) before any HTTPS data flows. If a packet is lost in transit, the receiver detects the gap via sequence numbers and the sender retransmits — ensuring ordered, reliable delivery between the two processes.

Contrast:
Layer 3 (Network) routes packets between networks. Layer 4 manages end-to-end reliability and uses ports to multiplex traffic between applications on the same host.`,
trick:"Layer 4 = Transport. 'Throw' in mnemonic. TCP/UDP, port numbers, reliability — think of the post office that tracks packages and ensures delivery."},

{cat:0,catName:"OSI Layers",acr:"Layer 5",full:"Session Layer",
def:`Definition:
The Session layer establishes, manages, and terminates communication sessions between applications. It handles session synchronization, checkpointing, and re-establishment after interruption. Relevant protocols: NetBIOS, RPC, PPTP (session establishment), SQL session management, SMB session negotiation.

Clue:
Look for session establishment, session tokens, login sessions, dialog control, or re-synchronization. Often blurry on the exam — focus on session creation, maintenance, and termination as key concepts.

Example:
A remote user connects to a corporate VPN during a large file transfer — when the link drops briefly, the application resumes automatically from its last saved checkpoint without re-authenticating. Synchronization checkpoints are created every 30 seconds to enable this recovery.

Contrast:
Layer 4 (Transport) handles the mechanics of reliable data transfer. Layer 5 (Session) manages the higher-level concept of a conversation or session between two applications.`,
trick:"Layer 5 = Session. 'Sausage' in mnemonic. Sessions, logins, checkpoints — think of a phone call being set up, held, and hung up."},

{cat:0,catName:"OSI Layers",acr:"Layer 6",full:"Presentation Layer",
def:`Definition:
The Presentation layer translates data between the application format and the network format. Responsibilities: data encoding/decoding, encryption/decryption, and compression/decompression. Examples: TLS/SSL encryption, JPEG/PNG image encoding, ASCII/Unicode character encoding, MIME encoding for email.

Clue:
Look for data format translation, encryption at the protocol level, or encoding schemes. TLS encrypts data at this layer before it is passed to the Transport layer. If a question mentions SSL/TLS in the context of data format, Presentation layer is the answer.

Example:
A web server sends an HTTP response — before transmission, the payload is encrypted into ciphertext using TLS cipher suites, UTF-8 encoded, and GZIP compressed. All of this format translation and encryption occurs at a single OSI layer before the data is handed to the transport mechanism.

Contrast:
Layer 7 (Application) generates the actual data (HTML, email). Layer 6 (Presentation) formats and encrypts it for transmission. Layer 4 (Transport) then carries it reliably to the destination.`,
trick:"Layer 6 = Presentation. 'Pizza' in mnemonic. Encryption, encoding, formatting — think of a translator converting between languages before sending a message."},

{cat:0,catName:"OSI Layers",acr:"Layer 7",full:"Application Layer",
def:`Definition:
The Application layer is the topmost layer — the one end-user applications and protocols interact with directly. It provides network services to applications. Key protocols: HTTP/HTTPS, DNS, SMTP/POP3/IMAP, FTP, SSH, SNMP, RDP, LDAP, Telnet. PDU: Data.

Clue:
Look for user-facing protocols, web traffic, email, DNS, or file transfer. Layer 7 is the layer you interact with directly. Almost all named protocols on the Security+ exam (HTTP, DNS, FTP, SMTP) live here. Web Application Firewalls (WAF) operate at Layer 7.

Example:
A user types a URL into a browser — DNS resolution (UDP/53) identifies the IP, HTTP/HTTPS (TCP/80 or 443) fetches the page, and SMTP (TCP/25) sends a contact form email — all are Layer 7 protocols.

Contrast:
Layer 6 (Presentation) handles encryption and encoding. Layer 7 is what the user or application sees and uses — the protocol names students memorize (HTTP, SSH, DNS, FTP) all live here.`,
trick:"Layer 7 = Application. 'Away' in mnemonic. HTTP, DNS, FTP, SSH, SNMP — the protocols you actually use. WAF defends here."},


// ══════════════════════════════════════════════════════════════
// cat:1  OSI ATTACKS  (acr = attack name, full = "Layer X — Name")
// _shortAns returns c.acr — quiz options are attack names
// ══════════════════════════════════════════════════════════════

{cat:1,catName:"OSI Attacks",acr:"MAC Flooding",full:"Layer 2 — Data Link Attack",
def:`Definition:
An attacker sends thousands of Ethernet frames with randomly spoofed source MAC addresses to overwhelm a switch's CAM (Content Addressable Memory) table. When the table is full, the switch can no longer map MACs to ports — it falls back to hub mode, broadcasting every frame to all ports. An attacker can then capture all traffic on the segment.

Clue:
Key phrase: "CAM table overflow," "switch broadcasts all traffic," or "switch acting like a hub." This is a Layer 2 attack because it targets MAC address tables and Ethernet frames.

Example:
An attacker on a university LAN runs macof to flood a switch with 155,000 fake MAC entries per minute — the switch's CAM table overflows and the attacker captures all student login traffic flowing through the switch.

Contrast:
ARP Poisoning targets individual hosts by corrupting their ARP caches. MAC Flooding targets the switch itself by exhausting its CAM table, forcing it to broadcast.`,
trick:"MAC Flooding = fill the switch's memory until it panics and shouts everything to everyone. Defense: port security (MAC limit per port)."},

{cat:1,catName:"OSI Attacks",acr:"ARP Poisoning",full:"Layer 2 — Data Link Attack",
def:`Definition:
An attacker on the local subnet sends unsolicited (gratuitous) ARP replies, mapping a legitimate IP address (such as the default gateway) to the attacker's MAC address. Victims update their ARP cache with the false mapping and send traffic to the attacker instead of the real destination — enabling MITM interception.

Clue:
Key phrases: "ARP cache poisoned," "attacker intercepts gateway traffic," "man-in-the-middle on LAN," or "gratuitous ARP." ARP operates at Layer 2 — no IP routing is involved.

Example:
An attacker broadcasts a fake ARP reply: "192.168.1.1 (gateway) is at AA:BB:CC:DD:EE:FF (attacker's MAC)" — all hosts on the subnet update their ARP cache and send traffic to the attacker, who forwards it to the real gateway while reading every packet.

Contrast:
MAC Flooding overflows the switch's CAM table to force broadcasting. ARP Poisoning targets host ARP caches to redirect traffic to the attacker specifically.`,
trick:"ARP Poisoning = lying to neighbors about who lives where. Defense: Dynamic ARP Inspection (DAI) on switches."},

{cat:1,catName:"OSI Attacks",acr:"VLAN Hopping",full:"Layer 2 — Data Link Attack",
def:`Definition:
An attacker bypasses VLAN segmentation to send traffic to a VLAN they should not have access to. Two methods: (1) Switch Spoofing — the attacker's device pretends to be a trunk port, negotiating 802.1Q trunking and receiving all VLAN traffic; (2) Double Tagging — the attacker adds two 802.1Q tags; the first switch strips the outer tag (native VLAN), and the second switch delivers the frame to the target VLAN based on the inner tag.

Clue:
Key phrases: "double-tagged frame," "trunk port negotiation," "bypassing VLAN segmentation," or "unauthorized VLAN access." This is a Layer 2 attack targeting 802.1Q VLAN tagging.

Example:
An attacker connects to a switch port in VLAN 10 and sends a double-tagged frame with outer VLAN 1 (native) and inner VLAN 99 (sensitive HR VLAN) — the first switch strips the outer tag; the second delivers the frame to VLAN 99, which the attacker cannot normally access.

Contrast:
MAC Flooding and ARP Poisoning do not cross VLAN boundaries. VLAN Hopping specifically exploits 802.1Q trunking to bypass the logical network segmentation that VLANs provide.`,
trick:"VLAN Hopping = sneaking into a restricted floor by abusing the elevator tag system. Fix: disable DTP, set access ports to 'access mode' only."},

{cat:1,catName:"OSI Attacks",acr:"IP Spoofing",full:"Layer 3 — Network Attack",
def:`Definition:
An attacker forges the source IP address in packet headers to impersonate a trusted host, bypass IP-based access controls, or hide their true origin. Used in DDoS amplification, session hijacking setup, and evading IP-based firewalls. Layer 3 attack because it manipulates IP packet headers.

Clue:
Key phrases: "forged source IP," "impersonating a trusted host," "bypassing IP-based ACL," or "DDoS amplification using spoofed source." IP spoofing operates at Layer 3 (Network layer).

Example:
An attacker sends DNS queries with the victim's IP as the source address to thousands of open DNS resolvers — each resolver sends a large DNS response to the victim, amplifying the attack volume by 50–70x and exhausting the victim's bandwidth.

Contrast:
ARP Poisoning spoofs at Layer 2 (MAC addresses). IP Spoofing operates at Layer 3 (IP addresses). Defense: Ingress filtering (BCP38) — ISPs block packets with source IPs not matching the originating network.`,
trick:"IP Spoofing = forging the return address on a package. Defense: ingress filtering (ISPs discard packets with impossible source IPs)."},

{cat:1,catName:"OSI Attacks",acr:"Smurf Attack",full:"Layer 3 — Network ICMP DDoS",
def:`Definition:
An attacker sends ICMP echo requests (pings) to a network's broadcast address with the victim's IP address forged as the source. Every host on the network responds to the victim simultaneously, amplifying the traffic volume by the number of hosts on the segment.

Clue:
Key phrases: "ICMP echo to broadcast address," "IP broadcast amplification," "hundreds of hosts reply to victim," or "ICMP-based DDoS." Smurf attacks exploit ICMP (Layer 3 protocol) and IP broadcast behavior.

Example:
An attacker spoofs the victim's IP and pings the broadcast address 192.168.1.255 — all 200 hosts on that subnet send ICMP replies to the victim, multiplying the traffic 200× and crashing the victim's connection.

Contrast:
A regular ICMP Ping Flood (one source pinging one target) is simpler. The Smurf attack amplifies the attack through IP broadcast — it was devastating before networks started blocking directed broadcasts. Defense: disable IP directed broadcasts on routers.`,
trick:"Smurf Attack = yell in a crowded room and point at the victim. All 200 people shout back at them. Block directed broadcast = soundproof each room."},

{cat:1,catName:"OSI Attacks",acr:"SYN Flood",full:"Layer 4 — Transport Attack",
def:`Definition:
An attacker sends a high volume of TCP SYN packets without completing the three-way handshake (never sending the final ACK). The server allocates resources (a half-open connection entry) for each SYN and waits for the ACK that never comes. The connection table fills up, and the server cannot accept legitimate connections.

Clue:
Key phrases: "half-open connections," "TCP handshake never completed," "connection table exhausted," or "server cannot accept new connections." SYN Flood targets TCP at Layer 4 (Transport layer).

Example:
An attacker uses spoofed source IPs to fire 50,000 SYN packets per second at a web server — the server creates 50,000 half-open TCP entries and times out waiting for ACKs, its connection table fills up, and legitimate users receive "connection refused."

Contrast:
A UDP Flood does not use the TCP handshake — it simply overwhelms bandwidth. A SYN Flood specifically exploits the stateful TCP three-way handshake. Defense: SYN cookies (allow server to avoid storing state until ACK arrives).`,
trick:"SYN Flood = keep knocking on the door and running away — the server holds the door open for you but nobody comes in. Defense: SYN cookies."},

{cat:1,catName:"OSI Attacks",acr:"Session Hijacking",full:"Layer 5 — Session Attack",
def:`Definition:
An attacker steals or predicts a valid session token and uses it to impersonate an authenticated user without knowing their password. Methods: packet sniffing (capturing session cookies over HTTP), XSS (stealing cookies via injected script), predictable session IDs, or token theft from storage.

Clue:
Key phrases: "stolen session token," "cookie theft," "attacker impersonates authenticated user," or "replays session ID." Session hijacking targets the session management layer — Layer 5 — and is closely associated with cookie theft at Layer 7.

Example:
An attacker on the same coffee shop Wi-Fi uses Wireshark to capture the victim's unencrypted HTTP session cookie, then replays it in their own browser — they are now logged in as the victim on the banking site without entering any credentials.

Contrast:
Credential theft (phishing, brute force) targets the login process. Session hijacking bypasses login entirely by stealing the token issued after login. Defense: HTTPS everywhere, HttpOnly + Secure cookie flags, short session timeouts.`,
trick:"Session Hijacking = stealing someone's parking ticket after they already paid — you use their authorization without re-doing the login."},

{cat:1,catName:"OSI Attacks",acr:"SSL Stripping",full:"Layer 6 — Presentation Attack",
def:`Definition:
An attacker acting as a MITM intercepts the victim's HTTP request before it upgrades to HTTPS. The attacker maintains an HTTPS connection to the server but serves the victim plain HTTP — the victim's browser shows HTTP while the server thinks it is communicating securely. The attacker reads all traffic in cleartext.

Clue:
Key phrases: "HTTPS downgraded to HTTP," "browser shows HTTP even though site supports HTTPS," "MITM intercepts before redirect," or "SSL stripping." This targets the encryption/decryption function at Layer 6 (Presentation).

Example:
A user visits http://bank.com at a coffee shop — the attacker intercepts the 302 redirect to https://bank.com, serves the user a plain HTTP version, and reads all submitted credentials in cleartext while forwarding them to the real HTTPS site.

Contrast:
A classic MITM attack intercepts already-encrypted traffic. SSL Stripping specifically prevents the encryption from being established in the first place. Defense: HSTS (HTTP Strict Transport Security) forces browsers to always use HTTPS.`,
trick:"SSL Stripping = removing the armor before the fight starts. Defense: HSTS tells browsers 'never connect without TLS, ever.'"},

{cat:1,catName:"OSI Attacks",acr:"Cross-Site Scripting",full:"Layer 7 — Application Attack",
def:`Definition:
An attacker injects malicious scripts into web content that is then served to other users' browsers. The injected script executes in the victim's browser under the trust of the legitimate site, enabling cookie theft, keylogging, or page defacement. Types: Stored XSS (script saved in database), Reflected XSS (script in URL/query), DOM-Based XSS (client-side manipulation).

Clue:
Key phrases: "injected script executes in victim's browser," "session cookie stolen via script," "malicious JavaScript in comment field," or "stored/reflected XSS." This is a Layer 7 Application layer attack — it exploits the web application itself.

Example:
An attacker posts a comment containing the script tag with document.cookie to a forum — every user who views the page executes the script in their browser and sends their session cookie to the attacker's server, allowing account takeover.

Contrast:
CSRF tricks the victim's browser into making requests. XSS injects malicious code that runs in the victim's browser. SQLi attacks the back-end database. All three are Layer 7 attacks. Defense: input sanitization, Content Security Policy (CSP), HttpOnly cookies.`,
trick:"XSS = hiding a bomb in someone's package that explodes when the recipient opens it. Defense: sanitize ALL user input, use CSP headers."},

{cat:1,catName:"OSI Attacks",acr:"DNS Cache Poisoning",full:"Layer 7 — Application Attack",
def:`Definition:
An attacker injects forged DNS records into a DNS resolver's cache. When clients query that resolver for a domain, they receive the attacker's malicious IP instead of the legitimate one, transparently redirecting all traffic to a fake server. The attack exploits the trust DNS resolvers place in responses without cryptographic validation.

Clue:
Key phrases: "forged DNS record in resolver cache," "DNS resolver returns wrong IP," "users redirected to fake site," or "DNS spoofing." This is a Layer 7 attack — DNS is an Application layer protocol (UDP/TCP port 53).

Example:
An attacker exploits a DNS resolver using a birthday attack to inject a forged A record for paypal.com pointing to 198.51.100.55 — all clients using that resolver are redirected to the attacker's phishing site and the legitimate PayPal site is unreachable for those users.

Contrast:
DNS Hijacking modifies DNS settings on a device or router. DNS Cache Poisoning specifically corrupts a shared resolver's cache, affecting all users of that resolver. Defense: DNSSEC (cryptographically signs DNS records), DNS over HTTPS (DoH).`,
trick:"DNS Cache Poisoning = changing street signs in a city so everyone goes to the wrong address. DNSSEC = digitally signed street signs."},


// ══════════════════════════════════════════════════════════════
// cat:2  OSI SECURITY CONTROLS  (acr = control name, full = "Layer X — Name")
// _shortAns returns c.acr — quiz options are control names
// ══════════════════════════════════════════════════════════════

{cat:2,catName:"OSI Controls",acr:"Dynamic ARP Inspection",full:"Layer 2 — Data Link Control",
def:`Definition:
DAI is a switch feature that validates ARP packets against a DHCP snooping binding table (IP-to-MAC-to-port mappings learned during DHCP). Any ARP reply that doesn't match a trusted binding is dropped, preventing ARP cache poisoning attacks.

Clue:
Key phrases: "validates ARP against DHCP snooping table," "drops unauthorized ARP replies," or "Layer 2 ARP protection on switch." DAI is the direct defense against ARP Poisoning attacks.

Example:
A switch with DAI enabled receives an ARP reply claiming 192.168.1.1 maps to AA:BB:CC:DD:EE:FF — it checks the DHCP snooping binding table, finds that IP was assigned to a different MAC, and drops the forged reply before any host can update its ARP cache.

Contrast:
Port security limits the number of MAC addresses per port (counters MAC Flooding). DAI validates ARP content against known good bindings (counters ARP Poisoning). Both are Layer 2 controls on the switch.`,
trick:"DAI = the switch fact-checks every ARP reply against its verified list. No matching record = dropped. Stops ARP Poisoning cold."},

{cat:2,catName:"OSI Controls",acr:"802.1X",full:"Layer 2 — Network Access Control",
def:`Definition:
IEEE 802.1X is a port-based Network Access Control (NAC) standard that requires devices to authenticate against a RADIUS server before being granted network access. Unauthenticated devices are kept in an unauthorized state — they may be quarantined to a restricted VLAN or blocked entirely. Used for wired Ethernet and WPA2/WPA3-Enterprise Wi-Fi.

Clue:
Key phrases: "authenticate before network access," "RADIUS server controls port access," "WPA2-Enterprise," or "EAP over LAN (EAPOL)." 802.1X operates at Layer 2 — the switch or WAP enforces authentication before allowing frames to flow.

Example:
A contractor plugs a laptop into a corporate switch port — the switch immediately holds all frames and demands authentication credentials via EAP before allowing any traffic. The laptop must prove its identity to the RADIUS server, or the port stays locked in a restricted quarantine VLAN with no access to corporate resources.

Contrast:
Port security controls which MAC addresses can use a port. 802.1X requires full authentication (username/password or certificate) before the port is opened. 802.1X is the stronger, identity-based control.`,
trick:"802.1X = show your ID before the door opens. The switch is the bouncer; RADIUS is the guest list. Used in WPA2/WPA3-Enterprise Wi-Fi too."},

{cat:2,catName:"OSI Controls",acr:"Packet Filter Firewall",full:"Layer 3 — Network Firewall",
def:`Definition:
A stateless packet filtering firewall inspects each packet individually based on static rules: source/destination IP address, source/destination port, and protocol (TCP/UDP/ICMP). It does not track connection state — each packet is evaluated independently. ACLs on routers are the most common implementation.

Clue:
Key phrases: "inspects individual packets," "IP address and port rules," "stateless," "ACL on router," or "no connection tracking." Packet filters operate at Layer 3 (and partially Layer 4 for ports) without session awareness.

Example:
A border router ACL allows inbound TCP port 443 from any source to the web server (10.0.1.5) and blocks everything else — every packet is checked against these rules independently, with no memory of prior packets.

Contrast:
A stateful firewall tracks TCP connection state and only allows packets that belong to established sessions. A packet filter cannot detect a TCP packet with no matching SYN — it just checks rules. Packet filters are faster but less secure.`,
trick:"Packet Filter Firewall = a bouncer who checks each ticket in isolation — no memory of whether you already came in or who you came with."},

{cat:2,catName:"OSI Controls",acr:"Stateful Firewall",full:"Layer 4 — Transport Firewall",
def:`Definition:
A stateful inspection firewall tracks the state of active TCP/UDP connections in a state table. It allows return traffic for established sessions automatically and blocks packets that claim to be part of a session that was never initiated. This prevents many spoofed-packet attacks that fool stateless packet filters.

Clue:
Key phrases: "tracks connection state," "state table," "allows established sessions," "blocks out-of-state packets," or "stateful inspection." Stateful firewalls operate at Layer 4 — they understand TCP handshake states (SYN, SYN-ACK, ACK, FIN, RST).

Example:
An internal host sends a TCP SYN to a web server — the firewall logs this outbound request in its connection table. When the server replies with SYN-ACK, the firewall matches the reply to the recorded outbound session and allows it inbound automatically, without needing any explicit inbound allow rule.

Contrast:
A packet filter checks rules but has no memory. A stateful firewall remembers which sessions were initiated and blocks reply packets that have no matching outbound session. Stateful = smarter, more secure, but uses more memory.`,
trick:"Stateful Firewall = a bouncer who remembers you went through the entry door — only lets you back out if you actually came in. Layer 4 awareness."},

{cat:2,catName:"OSI Controls",acr:"IPSec",full:"Layer 3 — Network Encryption",
def:`Definition:
IPSec (Internet Protocol Security) is a suite of protocols that authenticates and encrypts IP packets at the Network layer. Two modes: Transport mode (encrypts only the payload, keeps original IP header) and Tunnel mode (encrypts the entire original packet, adds new IP header — used for VPNs). Protocols: AH (Authentication Header) for integrity only; ESP (Encapsulating Security Payload) for encryption and integrity. Uses IKE (port 500) for key exchange.

Clue:
Key phrases: "encrypts at Layer 3," "site-to-site VPN," "AH or ESP protocol," "IKE key exchange," or "tunnel mode / transport mode." IPSec operates at the Network layer — it is transparent to applications.

Example:
Two branch offices establish an IPSec site-to-site VPN in tunnel mode — all traffic between sites is encapsulated in ESP packets and encrypted before traversing the internet, with IKE negotiating keys on UDP port 500.

Contrast:
TLS encrypts at Layer 4/6 and is application-aware. IPSec encrypts at Layer 3 and is transparent to all applications — everything in the IP packet is protected. IPSec VPNs are common for site-to-site connections.`,
trick:"IPSec = armor welded onto the packet at Layer 3. AH = integrity only; ESP = encryption + integrity. Tunnel mode = used for VPNs."},

{cat:2,catName:"OSI Controls",acr:"TLS",full:"Layer 4/6 — Transport/Presentation Encryption",
def:`Definition:
TLS (Transport Layer Security) provides encrypted, authenticated communication between two endpoints. It negotiates cipher suites, verifies server identity via certificates, and creates a symmetric session key through the TLS handshake. TLS 1.3 eliminated weak ciphers, removed RSA key exchange, and mandated forward secrecy. Protects HTTP (→ HTTPS), SMTP, LDAP (→ LDAPS), and many other protocols.

Clue:
Key phrases: "TLS handshake," "certificate verification," "encrypted channel," "HTTPS," or "cipher suite negotiation." TLS spans Layers 4-6 — it establishes a reliable connection (L4), then encrypts and formats data (L6) for applications (L7).

Example:
A browser connects to https://bank.com — the client and server perform a 1-RTT handshake, the server presents a certificate signed by a trusted CA, the browser verifies the certificate, they derive a shared symmetric key via forward-secret key exchange, and all subsequent HTTP data flows inside the encrypted channel.

Contrast:
IPSec encrypts entire IP packets at Layer 3 — it is transparent to applications. TLS encrypts at the application level — each application (browser, email client) must be TLS-aware. TLS 1.0/1.1 are deprecated; use TLS 1.2 minimum, TLS 1.3 preferred.`,
trick:"TLS = a sealed envelope around your HTTP. The browser checks the sender's signature (certificate) before reading it. TLS 1.3 = current gold standard."},

{cat:2,catName:"OSI Controls",acr:"WAF",full:"Layer 7 — Application Firewall",
def:`Definition:
A Web Application Firewall (WAF) inspects HTTP/HTTPS traffic at the Application layer and applies rules to detect and block application-layer attacks: SQL injection, XSS, CSRF, path traversal, and OWASP Top 10 vulnerabilities. A WAF understands web application context — HTTP methods, headers, cookies, and request bodies — unlike network firewalls.

Clue:
Key phrases: "inspects HTTP requests," "blocks SQL injection or XSS," "application-aware firewall," or "OWASP Top 10 protection." A WAF is the Layer 7 security control — it is the answer whenever a question asks about blocking web application attacks.

Example:
A WAF deployed in front of an e-commerce site detects an HTTP POST body containing 'OR 1=1 --' (classic SQL injection) and blocks the request with a 403 response before it ever reaches the application server or database.

Contrast:
A network firewall or stateful firewall operates at Layers 3-4 and cannot inspect HTTP request content. A WAF operates at Layer 7 and understands application semantics. Both may be used together: the network firewall blocks non-web traffic; the WAF blocks application-layer attacks on port 80/443.`,
trick:"WAF = the smart bouncer who reads the actual message you're passing in, not just the envelope. Network firewall = checks the address; WAF = checks the content."},

{cat:2,catName:"OSI Controls",acr:"HSTS",full:"Layer 7 — HTTP Security Header",
def:`Definition:
HSTS (HTTP Strict Transport Security) is an HTTP response header that instructs browsers to only connect to a domain over HTTPS, never HTTP. Once a browser sees the HSTS header, it will automatically convert all future HTTP requests to HTTPS for the specified duration — even before a redirect is issued. This prevents SSL Stripping attacks.

Clue:
Key phrases: "forces HTTPS," "prevents HTTP downgrade," "browser remembers to use TLS," or "defense against SSL stripping." HSTS is a Layer 7 (Application) control enforced through an HTTP header.

Example:
A bank's server sends "Strict-Transport-Security: max-age=31536000; includeSubDomains" — the user's browser caches this and for the next year, automatically uses HTTPS for all connections to that domain, even if a user types http:// — the SSL Stripping attack fails because the browser never sends an HTTP request.

Contrast:
TLS encrypts the connection. HSTS ensures the browser always initiates TLS from the start — it is the policy enforcement layer on top of TLS. Without HSTS, an SSL Stripping attacker can intercept the initial HTTP request before the TLS redirect.`,
trick:"HSTS = the browser's standing order: 'Never talk to this site without armor.' Remembers the rule for up to 1 year. Kills SSL Stripping dead."},

];
