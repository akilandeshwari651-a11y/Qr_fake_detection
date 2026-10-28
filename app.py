import streamlit as st
import cv2
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode
import re
import socket
import requests
import tldextract
import whois
from datetime import datetime
import ssl
import urllib.parse

# ---------- CONFIG ----------
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.zip', '.mov'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
              'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy'}
PHISHING_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'confirm',
                     'banking', 'wallet', 'signin', 'password', 'kyc', 'refund']
BRAND_NAMES = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
               'netflix', 'sbi', 'hdfc', 'icici', 'phonepe', 'paytm', 'gpay']

# ---------- CORE FUNCTIONS ----------
def decode_qr(image: Image.Image):
    """Extract all URLs/payloads from an image."""
    img_array = np.array(image.convert('RGB'))
    results = decode(img_array)
    payloads = []
    for r in results:
        try:
            payloads.append(r.data.decode('utf-8'))
        except:
            payloads.append(r.data.decode('latin-1', errors='ignore'))
    return payloads, img_array

def analyze_url(url: str) -> dict:
    """Multi-layer URL risk analysis."""
    findings = []
    score = 0
    parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
    domain = parsed.netloc.lower()
    ext = tldextract.extract(domain)

    # 1. Protocol
    if parsed.scheme == 'http':
        findings.append(("⚠️", "Uses HTTP (no TLS encryption)")); score += 10

    # 2. IP-based URL
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]):
        findings.append(("🚨", "IP address instead of domain name")); score += 35

    # 3. Suspicious TLD
    if f".{ext.suffix}" in SUSPICIOUS_TLDS:
        findings.append(("⚠️", f"Risky TLD: .{ext.suffix}")); score += 20

    # 4. URL shortener
    if any(s in domain for s in SHORTENERS):
        findings.append(("⚠️", "URL shortener hides real destination")); score += 15

    # 5. Typosquatting / brand impersonation
    for brand in BRAND_NAMES:
        if brand in domain and brand not in ext.domain:
            findings.append(("🚨", f"Possible '{brand}' impersonation")); score += 30
            break
        # Levenshtein-lite check: brand + extra chars in odd places
        if ext.domain and brand in ext.domain and ext.domain != brand:
            if abs(len(ext.domain) - len(brand)) <= 2 and ext.domain != brand:
                findings.append(("⚠️", f"Lookalike domain for '{brand}'")); score += 25

    # 6. Excessive subdomains / hyphens
    if domain.count('.') > 3:
        findings.append(("⚠️", "Unusually many subdomains")); score += 15
    if domain.count('-') > 2:
        findings.append(("⚠️", "Many hyphens in domain")); score += 10

    # 7. Phishing keywords
    path_q = (parsed.path + '?' + parsed.query).lower()
    hits = [k for k in PHISHING_KEYWORDS if k in path_q or k in domain]
    if hits:
        findings.append(("⚠️", f"Phishing keywords: {', '.join(hits[:3])}")); score += 10 * min(len(hits), 3)

    # 8. Unicode / homoglyph detection
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        findings.append(("🚨", "Punycode/Unicode domain (homoglyph risk)")); score += 30

    # 9. DNS / WHOIS checks
    age_days = None
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            if age_days < 30:
                findings.append(("🚨", f"Domain registered {age_days} days ago")); score += 30
            elif age_days < 90:
                findings.append(("⚠️", f"New domain ({age_days} days old)")); score += 15
    except Exception:
        findings.append(("⚠️", "WHOIS lookup failed / no record")); score += 10

    # 10. SSL certificate check
    if parsed.scheme == 'https':
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(4); s.connect((domain, 443))
        except Exception:
            findings.append(("⚠️", "Invalid or unreachable TLS certificate")); score += 15

    # 11. Redirect chain trace
    redirect_chain = []
    try:
        r = requests.get(url if '://' in url else 'http://' + url,
                         timeout=5, allow_redirects=True, stream=True)
        for h in r.history:
            redirect_chain.append(h.headers.get('Location', ''))
        final = r.url
        if final != url and final:
            redirect_chain.append(final)
            findings.append(("⚠️", f"Redirects to: {final}")); score += 10
    except Exception:
        findings.append(("⚠️", "Could not resolve destination")); score += 10

    score = min(score, 100)
    if score >= 60:   verdict, color = "DANGEROUS", "red"
    elif score >= 30: verdict, color = "SUSPICIOUS", "orange"
    else:             verdict, color = "LIKELY SAFE", "green"

    return {
        "url": url, "domain": domain, "score": score,
        "verdict": verdict, "color": color,
        "findings": findings, "age_days": age_days,
        "redirect_chain": redirect_chain,
    }

def highlight_url(url: str, findings: list) -> str:
    """Return URL with suspicious parts wrapped in markup."""
    parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
    domain = parsed.netloc
    ext = tldextract.extract(domain)
    flagged_tld = f".{ext.suffix}" in SUSPICIOUS_TLDS
    flagged_brand = any(b in domain and b not in ext.domain for b in BRAND_NAMES)
    flagged_http = parsed.scheme == 'http'

    color = "#c0392b" if (flagged_tld or flagged_brand) else ("#e67e22" if flagged_http else "#27ae60")
    return f"""
    <div style="font-family:monospace;padding:12px;border-radius:8px;background:#f4f4f4;word-break:break-all;font-size:15px;">
      <span style="color:#7f8c8d;">{parsed.scheme}://</span>
      <span style="background:{color}22;color:{color};font-weight:bold;padding:2px 4px;border-radius:4px;">{domain}</span>
      <span>{parsed.path}{('?'+parsed.query) if parsed.query else ''}</span>
    </div>"""

# ---------- STREAMLIT UI ----------
st.set_page_config(page_title="QR Safety Scanner", page_icon="🛡️", layout="wide")
st.title("🛡️ QR Code Safety Scanner")
st.caption("Scan → Analyze → Warn — before you click")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("1. Provide a QR code")
    uploaded = st.file_uploader("Upload QR image", type=["png","jpg","jpeg","webp"])
    use_cam = st.checkbox("Use webcam snapshot")
    cam_img = st.camera_input("Scan via camera") if use_cam else None

image = None
if uploaded: image = Image.open(uploaded)
elif cam_img: image = Image.open(cam_img)

if image:
    st.image(image, caption="Input QR", use_column_width=True)
    payloads, _ = decode_qr(image)
    if not payloads:
        st.error("❌ No QR code detected. Try a clearer image.")
    else:
        for p in payloads:
            st.success(f"Decoded: `{p}`")
            with st.spinner("Running 11-point risk analysis..."):
                report = analyze_url(p)

            st.markdown("### 🎯 Highlighted URL")
            st.markdown(highlight_url(p, report["findings"]), unsafe_allow_html=True)

            verdict_color = {"red":"#e74c3c","orange":"#e67e22","green":"#27ae60"}[report["color"]]
            st.markdown(f"""
            <div style="border-left:6px solid {verdict_color};padding:12px 18px;background:#fafafa;border-radius:6px;margin:12px 0;">
              <h3 style="margin:0;color:{verdict_color};">{report['verdict']} — Risk Score {report['score']}/100</h3>
            </div>""", unsafe_allow_html=True)

            st.markdown("#### 🔍 Findings")
            if report["findings"]:
                for icon, msg in report["findings"]:
                    st.markdown(f"{icon} {msg}")
            else:
                st.markdown("✅ No red flags detected by static analysis.")

            with st.expander("📜 Redirect chain"):
                if report["redirect_chain"]:
                    for i, hop in enumerate(report["redirect_chain"], 1):
                        st.code(f"{i}. {hop}")
                else:
                    st.write("No redirects observed.")

            # ---------- WARNING GATE ----------
            if report["score"] >= 30:
                st.warning("⚠️ This link may be unsafe. Do you still want to continue?")
                c1, c2 = st.columns(2)
                if c1.button("🚫 Cancel — Stay Safe", use_container_width=True):
                    st.info("Cancelled. No navigation performed.")
                if c2.button("▶️ Proceed at my own risk", use_container_width=True):
                    st.error(f"You chose to proceed to: {report['url']}\n\n(Navigation blocked in prototype)")
            else:
                st.success("✅ Looks safe. You may proceed.")
                st.markdown(f"[➡️ Open destination]({report['url']})")

            st.divider()

with col2:
    st.subheader("2. Quick test URLs")
    st.markdown("Paste a URL to test the analyzer without a QR:")
    test_url = st.text_input("URL", placeholder="https://example.com/login")
    if test_url:
        r = analyze_url(test_url)
        st.markdown(highlight_url(test_url, r["findings"]), unsafe_allow_html=True)
        st.markdown(f"**{r['verdict']}** (score {r['score']})")
        for icon, msg in r["findings"]:
            st.write(f"{icon} {msg}")
