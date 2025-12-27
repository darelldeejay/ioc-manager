
@app.route("/maintenance/toggle", methods=["POST"])
@login_required
def maintenance_toggle():
    global MAINTENANCE_MODE
    
    # Check admin role
    if session.get("role") != "admin":
        return jsonify({"error": "Requiere rol de admin"}), 403

    data = request.get_json(silent=True) or {}
    active = bool(data.get("active", False))
    
    MAINTENANCE_MODE = active
    
    # Audit logic
    current_user = session.get("username", "admin")
    _audit("maintenance_toggle", f"web/{current_user}", "global", {"active": active})
    
    # Notify Teams
    state_str = "ACTIVADO" if active else "DESACTIVADO"
    color = "DC3545" if active else "28A745"
    send_teams_alert(
        f"⚠️ Mantenimiento {state_str}",
        f"El modo mantenimiento ha sido **{state_str}** por **{current_user}**.",
        color=color,
        sections=[{"activityTitle": "User", "activitySubtitle": current_user}]
    )
    
    return jsonify({"success": True, "active": active})
