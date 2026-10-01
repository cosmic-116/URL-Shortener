import io
import re
import threading
from flask import Blueprint, request, abort, render_template, current_app, Response

import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers.pil import RoundedModuleDrawer
from qrcode.image.styles.colormasks import RadialGradiantColorMask

import db
import core
from blueprints.helpers import build_short_url, login_required

qr_bp = Blueprint('qr', __name__)

_QR_CACHE_MAX = 500
_qr_cache = {}
_qr_cache_lock = threading.Lock()

def _generate_qr(data, style='basic'):
    """Generates a QR code image as PNG in-memory bytes."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    if style == 'styled':
        img = qr.make_image(
            image_factory=StyledPilImage,
            module_drawer=RoundedModuleDrawer(),
            color_mask=RadialGradiantColorMask(
                back_color=(4, 4, 7),
                center_color=(255, 255, 255),
                edge_color=(59, 130, 246),
            ),
        )
    else:
        img = qr.make_image(fill_color='black', back_color='white')

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf

def _get_cached_qr(data, style='basic'):
    """In-memory bounded LRU cache for generated QR PNG bytes."""
    key = (data, style)
    with _qr_cache_lock:
        if key in _qr_cache:
            val = _qr_cache.pop(key)
            _qr_cache[key] = val
            return val

    val = _generate_qr(data, style).getvalue()
    with _qr_cache_lock:
        if len(_qr_cache) >= _QR_CACHE_MAX:
            _qr_cache.pop(next(iter(_qr_cache)))
        _qr_cache[key] = val
    return val

def _serve_qr_helper(code, style='basic', as_download=False):
    """Consolidated helper to validate, rate-limit, and return QR PNG response."""
    if not re.fullmatch(r'^[A-Za-z0-9_-]{1,30}$', code):
        abort(404)

    ip = request.remote_addr or 'unknown'
    if core.is_rate_limited(f"qr:{ip}", max_requests=30, window_seconds=60):
        return render_template('429.html'), 429

    conn = db.get_db()
    link = conn.execute('SELECT code FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
    if not link:
        abort(404)

    short_url = build_short_url(code)
    qr_data = _get_cached_qr(short_url, style=style)

    headers = {
        'Cache-Control': 'public, max-age=3600',
        'X-Content-Type-Options': 'nosniff'
    }
    if as_download:
        headers['Content-Disposition'] = f'attachment; filename=snip-qr-{code}.png'

    return Response(qr_data, mimetype='image/png', headers=headers)

@qr_bp.route('/qr/<code>', endpoint='qr_basic')
def qr_basic(code):
    """Serve a basic QR code for a short link with caching and rate limiting."""
    return _serve_qr_helper(code, style='basic', as_download=False)

@qr_bp.route('/qr/<code>/styled', endpoint='qr_styled')
@login_required
def qr_styled(code):
    """Serve a styled QR code with gradient."""
    return _serve_qr_helper(code, style='styled', as_download=False)

@qr_bp.route('/qr/<code>/download', endpoint='qr_download')
@login_required
def qr_download(code):
    """Download styled QR code as PNG file."""
    return _serve_qr_helper(code, style='styled', as_download=True)

@qr_bp.route('/qr/<code>/download-basic', endpoint='qr_download_basic')
def qr_download_basic(code):
    """Download the basic black-on-white QR code as a PNG file."""
    return _serve_qr_helper(code, style='basic', as_download=True)
