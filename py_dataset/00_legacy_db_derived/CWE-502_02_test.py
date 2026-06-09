from flask import Flask, request, jsonify
import yaml

app = Flask(__name__)

def normalize_config(config):
    if config is None:
        return {}
    return config

@app.route("/admin/config/import", methods=["POST"])
def import_config():
    config_file = request.files["config"]
    config_text = config_file.read().decode("utf-8")

    config = yaml.load(config_text, Loader=yaml.Loader)
    config = normalize_config(config)

    return jsonify({
        "message": "config imported",
        "keys": list(config.keys()) if isinstance(config, dict) else [],
    })
