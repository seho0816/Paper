from flask import Flask, request
import json
 
app = Flask(__name__)
 
@app.route('/process-payment', methods=['POST'])
def process():
    CCNumber = request.form.get('cc')
    expDate = request.form.get('expDate')
    CVV = request.form.get('CVV')
    orderNumber = request.form.get('orderNumber')
    success = processPayment(CCNumber, expDate, CVV, orderNumber)
 
    # Log payment status to log file
    with open('log.txt', 'a') as log_file:
        log_file.write("PAYMENT " + orderNumber + " " + success + "\n")
 
app.run(host="0.0.0.0")