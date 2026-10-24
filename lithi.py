from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ----------------------------------------------------------------
# ML-READY ANALYSIS ENGINE (Rule-Based for Version 1)
# ----------------------------------------------------------------
def analyze_message_heuristics(message_text):
    """
    Analyzes text for phishing indicators using a structured rule engine.
    This architecture is completely separated from the routing layer so you
    can easily swap this function out for an ML model prediction later.
    """
    text_lower = message_text.lower()
    warning_signs = []
    
    # 1. Urgent/Threatening Language Vector
    urgency_words = ['urgent', 'suspension', 'freeze', '24 hours', 'immediately', 'compromised', 'final notice', 'action required']
    matched_urgency = [word for word in urgency_words if word in text_lower]
    if len(matched_urgency) >= 2:
        warning_signs.append({
            "vector": "Urgent Language",
            "severity": "High",
            "detail": f"Creates artificial panic or artificial deadlines using terms like: {', '.join(matched_urgency[:3])}."
        })

    # 2. Credential Harvesting Vector
    credential_words = ['password', 'login', 'credentials', 'username', 'passcode', 'security token']
    matched_credentials = [word for word in credential_words if word in text_lower]
    if matched_credentials:
        warning_signs.append({
            "vector": "Credential Harvesting",
            "severity": "High",
            "detail": f"Directly references portal access parameters ({', '.join(matched_credentials)}). Authorized administrators never solicit passwords."
        })

    # 3. Sensitive / Financial Data Request Vector
    sensitive_words = ['bank account', 'credit card', 'ssn', 'social security', 'verify identity', 'account number', 'routing number']
    matched_sensitive = [word for word in sensitive_words if word in text_lower]
    if matched_sensitive:
        warning_signs.append({
            "vector": "Sensitive Data Inquiries",
            "severity": "Medium",
            "detail": f"References financial or high-value identity parameters ({', '.join(matched_sensitive)})."
        })

    # 4. Suspicious Hyperlink Patterns Vector
    link_words = ['http://', 'click here', 'login-update', 'secure-verify', '.com/']
    matched_links = [word for word in link_words if word in text_lower]
    if matched_links:
        warning_signs.append({
            "vector": "Suspicious Hyperlink Indicators",
            "severity": "Medium",
            "detail": "Contains direct navigation prompts or unverified link patterns."
        })

    # Determining Risk Category
    has_high_severity = any(sign["severity"] == "High" for sign in warning_signs)
    
    if has_high_severity:
        risk_category = "High"
        explanation = "This message matches multiple standard aggressive phishing vectors. It actively leverages psychological urgency or credential harvesting patterns."
        safety_recommendations = [
            "Do not click any embedded links or open unexpected attachments.",
            "Never supply passwords, secondary PINs, or verification codes via message channels.",
            "Verify the authenticity independently by dialing your institution's official helpline."
        ]
    elif len(warning_signs) > 0:
        risk_category = "Medium"
        explanation = "The communication contains baseline indicators frequently associated with untrusted sources, such as suspicious external references."
        safety_recommendations = [
            "Hover over links to inspect the destination URL before clicking.",
            "Confirm the sender email domain exactly matches the official institution address."
        ]
    else:
        risk_category = "Low"
        explanation = "No standard automated phishing keyword sequences or typical high-urgency language patterns were flagged during the heuristic check."
        safety_recommendations = [
            "Even if low risk, remain vigilant if this message comes from an unknown sender.",
            "Targeted, highly specific attacks (spear phishing) may avoid generic filter keywords."
        ]

    return {
        "risk_category": risk_category,
        "warning_signs": warning_signs,
        "explanation": explanation,
        "safety_recommendations": safety_recommendations
    }

# ----------------------------------------------------------------
# FLASK WEB SERVER ROUTING LAYERS
# ----------------------------------------------------------------

@app.route('/')
def home():
    """Renders your existing hackathon frontend."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """API endpoint evaluating message contents securely entirely in memory."""
    # Validate JSON payload structure
    if not request.is_json:
        return jsonify({"error": "Unsupported Media Type. Request body must be JSON."}), 415

    data = request.get_json()
    message_text = data.get('message', '')

    # Requirement 5: Handle empty or whitespace-only messages properly
    if not message_text.strip():
        return jsonify({
            "error": "Bad Request",
            "message": "The message input box cannot be empty. Please supply text to analyze."
        }), 400

    # Execute rule-based analysis (Privacy preserved: data is processed in-memory, never saved)
    result = analyze_message_heuristics(message_text)
    
    return jsonify(result), 200

if __name__ == '__main__':
    # Run server locally on default port 5000
    app.run(debug=False)
