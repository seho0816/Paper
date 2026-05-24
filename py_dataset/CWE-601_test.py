@app.route("/login", methods=['GET', 'POST'])
def login():
   form = LoginForm()
   if form.validate_on_submit():
       if auth(username, password):
           redirect_url = request.args.get('redirect_url', '/')
           return redirect(redirect_url)
       else:
           flash('Incorrect Credentials Supplied')
   return render_template('login.html', form=form)