import streamlit as st
import pandas as pd

from url_analyzer import analyze_url
from dns_checker import check_dns


# PAGE SETTINGS
st.set_page_config(
    page_title="PHISHGUARD",
    page_icon="🛡️",
    layout="wide"
)


# WEBSITE DESIGN
st.markdown("""
<style>

.stApp {
    background-color: #080f1e;
    color: white;
}

.block-container {
    max-width: 1200px;
    padding-top: 2rem;
}

.main-title {
    text-align: center;
    font-size: 45px;
    font-weight: 800;
    color: #32c5ff;
}

.subtitle {
    text-align: center;
    color: #9fb2cc;
    margin-bottom: 35px;
}

.stButton > button {
    background-color: #087fc4;
    color: white;
    border-radius: 8px;
    border: none;
    height: 45px;
    font-weight: bold;
}

div[data-testid="stMetric"] {
    background-color: #14243c;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #234363;
}

</style>
""", unsafe_allow_html=True)


# HEADER
st.markdown(
    '<div class="main-title">🛡️ PHISHGUARD</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'PHISHING WEBSITE DETECTION SYSTEM'
    '</div>',
    unsafe_allow_html=True
)

st.divider()


# SIDEBAR
st.sidebar.title("🛡️ PHISHGUARD")

st.sidebar.markdown("### Navigation")

st.sidebar.write("🏠 Dashboard")
st.sidebar.write("🔍 URL Scanner")
st.sidebar.write("📊 Analysis")
st.sidebar.write("📁 Scan History")

st.sidebar.divider()

st.sidebar.info(
    "Educational cybersecurity project "
    "for suspicious URL analysis."
)


# SCAN HISTORY
if "history" not in st.session_state:
    st.session_state.history = []


# URL SCANNER
st.subheader("🔍 Website URL Scanner")

st.write(
    "Enter a website URL to analyse its "
    "suspicious characteristics."
)

with st.form("scanner_form"):

    url = st.text_input(
        "Enter Website URL",
        placeholder="Example: https://example.com"
    )

    scan_button = st.form_submit_button(
        "SCAN WEBSITE",
        use_container_width=True
    )


# SCANNING
if scan_button:

    try:

        with st.spinner("Analysing website URL..."):

            result = analyze_url(url)

            dns_result = check_dns(
                result["domain"]
            )

        result["dns"] = dns_result

        st.session_state.current_result = result

        st.session_state.history.insert(
            0,
            {
                "URL": result["url"],
                "Risk Score": result["score"],
                "Risk Level": result["risk"]
            }
        )

        st.success("URL analysis completed!")

    except ValueError as error:

        st.error(str(error))


# DISPLAY RESULTS
if "current_result" in st.session_state:

    result = st.session_state.current_result

    st.divider()

    st.subheader("📊 SCAN RESULTS")
        # SET RISK COLOURS

    if result["risk"] == "LOW":
        risk_color = "#22c55e"
        risk_background = "#102d20"

    elif result["risk"] == "MEDIUM":
        risk_color = "#f59e0b"
        risk_background = "#382710"

    else:
        risk_color = "#ef4444"
        risk_background = "#381717"
        # DISPLAY COLOURFUL RISK CARDS

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"""
            <div style="
                background-color: {risk_background};
                border: 1px solid {risk_color};
                border-radius: 12px;
                padding: 20px;
                text-align: center;
            ">
                <p style="color: white;">RISK SCORE</p>
                <h1 style="color: {risk_color};">
                    {result["score"]}/100
                </h1>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div style="
                background-color: {risk_background};
                border: 1px solid {risk_color};
                border-radius: 12px;
                padding: 20px;
                text-align: center;
            ">
                <p style="color: white;">RISK LEVEL</p>
                <h1 style="color: {risk_color};">
                    {result["risk"]}
                </h1>
            </div>
        """, unsafe_allow_html=True)
    

        

    # RISK MESSAGE
    if result["risk"] == "HIGH":

        st.error(
            "Several suspicious indicators detected!"
        )

    elif result["risk"] == "MEDIUM":

        st.warning(
            "Some suspicious indicators detected."
        )

    else:

        st.success(
            "Few suspicious indicators detected."
        )


    # URL DETAILS
    st.subheader("🔎 URL ANALYSIS")

    st.write("Analysed URL:", result["url"])

    st.write("Domain:", result["domain"])

    for finding in result["findings"]:

        st.write("•", finding)


    # DNS DETAILS
    st.subheader("🌐 DNS INFORMATION")

    st.write(result["dns"]["status"])

    if result["dns"]["addresses"]:

        for address in result["dns"]["addresses"]:

            st.code(address)

    else:

        st.info("No IP addresses were returned.")
    st.warning(
    "LOW RISK does not guarantee that a website is safe. "
    "PHISHGUARD uses basic URL pattern analysis and cannot "
    "confirm whether a website is malicious."
)


    # DOWNLOAD REPORT
    st.subheader("📥 DOWNLOAD REPORT")

    report = pd.DataFrame([{
        "URL": result["url"],
        "Domain": result["domain"],
        "Risk Score": result["score"],
        "Risk Level": result["risk"],
        "DNS Status": result["dns"]["status"],
        "Findings": "; ".join(result["findings"])
    }])

    st.download_button(
        "Download CSV Report",
        report.to_csv(index=False),
        file_name="phishguard_report.csv",
        mime="text/csv"
    )


# SCAN HISTORY
st.divider()

st.subheader("📁 SCAN HISTORY")

if st.session_state.history:

    history_df = pd.DataFrame(
        st.session_state.history
    )

    st.dataframe(
        history_df,
        use_container_width=True,
        hide_index=True
    )

    if st.button("Clear History"):

        st.session_state.history = []

        st.rerun()

else:

    st.info("No previous scans yet.")


# FOOTER
st.divider()

st.markdown("""
<div style="text-align:center;color:#8296b0;">

PHISHGUARD<br>
Python Based Cybersecurity Project<br>
Educational Use Only

</div>
""", unsafe_allow_html=True)