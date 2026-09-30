from blueprints.auth import auth_bp
from blueprints.dashboard import dashboard_bp
from blueprints.api import api_bp
from blueprints.redirect import redirect_bp
from blueprints.qr import qr_bp

def register_blueprints(app):
    """Registers all application blueprints."""
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(qr_bp)
    # Register redirect_bp last so catch-all /<code> does not overshadow /dashboard, /api, /qr etc.
    app.register_blueprint(redirect_bp)
