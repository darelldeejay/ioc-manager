
@app.route('/api/estado/<path:ip>', methods=['GET'])
@require_api_token(required_scope='READ')
def api_get_status(ip):
    # Verify IP format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid IP format"}), 400

    # Get Status
    hist_list = db.get_ip_history(ip)
    
    # Get current details?
    # Spec says: history array.
    
    return jsonify({
        "ok": True,
        "ip": ip,
        "history": hist_list
    })
