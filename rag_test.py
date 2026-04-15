import google.generativeai as genai

genai.configure(api_key="AIzaSyCwOx1tLel-4xsHMhlc8ThMzHjw8QNCGtE")

model = genai.GenerativeModel('gemini-2.5-flash')

def login_user(username, password):
    query = f"SELECT * FROM users WHERE id = '{username}' AND pw = '{password}'"
    print(f"Executing: {query}")
    return query

def calculate_data(a, b):
    return a + b

print("Hello World")