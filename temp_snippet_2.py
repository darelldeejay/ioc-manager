

@app.route('/api/estado/<path:ip>', methods=['GET'])
@require_api_token(required_scope='READ')
def api_get_status(ip):
    row = db.get_ip(ip)
    if not row:
        return jsonify({"ok": False, "error": "IP not found"}), 404
        
    try:
        history = json.loads(row["history"] or '[]')
        history.sort(key=lambda x: x.get("ts", ""), reverse=True)
    except:
        history = []
        
    # Flatten/Cleanup for API? Or generic dump?
    # Spec says: history list.
    return jsonify({
        "ok": True,
        "ip": ip,
        "history": history
    })
