"""
PhishGuard AI — Multimodal Phishing Detection Prototype
Run: python -m streamlit run app.py
"""
from __future__ import annotations

from datetime import datetime

import streamlit as st

from engine import (
    BRAND_DIR,
    analyze_text,
    analyze_url,
    compare_brand_image,
    fuse_risk,
    reference_image_count,
)

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide")

if "history" not in st.session_state:
    st.session_state.history = []

with st.sidebar:
    st.header("PhishGuard AI")
    st.caption("Student-friendly multimodal phishing screening.")
    st.write(f"**Reference logos:** {reference_image_count()} in `{BRAND_DIR.name}/`")
    st.markdown(
        "- URL heuristics (HTTPS, TLD, lookalikes, RDAP, redirects)\n"
        "- Message social-engineering rules\n"
        "- Optional perceptual-hash logo check"
    )
    st.info(
        "Educational prototype, not a guarantee of safety. "
        "Do not paste passwords, OTPs, private keys, or other secrets. "
        "Network checks may contact the submitted domain."
    )
    if st.button("Clear scan history"):
        st.session_state.history = []
        st.rerun()

st.title("🛡️ PhishGuard AI")
st.write("Analyze a URL, message, screenshot, or any combination of the three.")

with st.form("scan_form"):
    url_input = st.text_input("Website URL (optional)", placeholder="https://example.com")
    message_input = st.text_area(
        "Suspicious email, SMS, or website text (optional)",
        placeholder="Paste message text here...",
        height=140,
    )
    image_input = st.file_uploader(
        "Logo or screenshot (optional)", type=["png", "jpg", "jpeg", "webp"]
    )
    submitted = st.form_submit_button("Analyze", type="primary")

if submitted:
    if not url_input.strip() and not message_input.strip() and image_input is None:
        st.error("Enter a URL, paste a message, or upload an image.")
    else:
        url_result = None
        text_result = None
        image_similarity = None
        image_message = "Image not provided"

        if url_input.strip():
            with st.spinner("Checking URL signals..."):
                url_result = analyze_url(url_input)
        if message_input.strip():
            text_result = analyze_text(message_input)
        if image_input is not None:
            image_similarity, image_message, _ = compare_brand_image(image_input)

        risk, label = fuse_risk(url_result, text_result, image_similarity)
        st.session_state.history.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "url": url_input.strip() or "—",
            "risk": risk,
            "label": label,
        })
        st.session_state.history = st.session_state.history[:8]
        st.session_state.last_scan = {
            "url_result": url_result,
            "text_result": text_result,
            "image_similarity": image_similarity,
            "image_message": image_message,
            "image_provided": image_input is not None,
            "risk": risk,
            "label": label,
        }

scan = st.session_state.get("last_scan")
if scan:
    url_result = scan["url_result"]
    text_result = scan["text_result"]
    risk = scan["risk"]
    label = scan["label"]

    st.divider()
    st.subheader("Overall result")
    c1, c2, c3 = st.columns(3)
    c1.metric("Combined risk score", f"{risk}/100")
    c2.metric("URL risk", f"{url_result['score']}/100" if url_result else "Not supplied")
    c3.metric("Text risk", f"{text_result['score']}/100" if text_result else "Not supplied")

    if label == "HIGH RISK":
        st.error("🚨 " + label)
    elif label == "SUSPICIOUS":
        st.warning("⚠️ " + label)
    else:
        st.success("🟢 " + label)
    st.caption("Scores are heuristic indicators, not calibrated probabilities.")

    col1, col2 = st.columns(2)
    with col1:
        if url_result:
            st.subheader("URL analysis")
            st.write("**Registered domain:**", url_result["domain"])
            st.write("**Domain age:**", url_result["age"])
            st.write("**Hostname entropy:**", url_result.get("entropy", "N/A"))
            for finding in url_result["findings"]:
                st.write("• " + finding)
            if url_result["redirects"]:
                with st.expander("Observed redirect chain"):
                    for hop in url_result["redirects"]:
                        st.code(hop)
    with col2:
        if text_result:
            st.subheader("Message analysis")
            st.write(f"**Matched categories:** {text_result['categories_matched']}")
            for finding in text_result["findings"]:
                st.write("• " + finding)
        if scan["image_provided"]:
            st.subheader("Image analysis")
            st.write(scan["image_message"])

    st.subheader("Suggested next step")
    if risk >= 60:
        st.write(
            "Avoid opening the link, submitting credentials, or paying. "
            "Verify the request using a separately obtained official website or phone number."
        )
    elif risk >= 30:
        st.write(
            "Pause before interacting. Check the sender and domain and verify "
            "the request through a separate trusted channel."
        )
    else:
        st.write(
            "No strong indicators were found by the available checks. "
            "This does not prove the content is legitimate."
        )

if st.session_state.history:
    st.divider()
    st.subheader("Recent scans (this session)")
    st.dataframe(
        st.session_state.history,
        use_container_width=True,
        hide_index=True,
    )

st.divider()
with st.expander("How to enable logo matching"):
    st.write(
        "Place reference images you are authorized to use inside the "
        "`trusted_brands` folder (PNG, JPG, JPEG, or WEBP). Name files clearly, "
        "for example `google.png`. The prototype compares perceptual hashes; "
        "for production, use OCR and image embeddings and verify domain ownership."
    )
st.caption(
    "PhishGuard AI | Student cybersecurity project | Use only for authorized defensive analysis"
)
