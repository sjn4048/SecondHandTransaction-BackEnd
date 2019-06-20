from flask import render_template
from ThriftShop import app

@app.errorhandler(404)
def page_not_found(e):
    from ThriftShop.models import User
    user = User.query.first()
    return render_template('errors/404.html', user=user), 404
