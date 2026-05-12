# Endpoint allowing arbitrary property updates
@app.route('/api/booking/update', methods=['POST'])
def update_booking():
    booking = get_booking(request.json['id'])
    for key, value in request.json.items():
        setattr(booking, key, value)  # Allows unrestricted updates
    save_booking(booking)
    return jsonify(booking)