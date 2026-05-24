def logo():
    img = request.args.get('image_name')

    return send_file(os.path.join(os.getcwd(), img))