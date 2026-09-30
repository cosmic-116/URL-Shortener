import os
from flask import Blueprint, request, jsonify, session, g

import db
import core
from blueprints.helpers import (require_api_key, _shorten_logic,
                                _delete_screenshot_file)

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/shorten', methods=['POST'], endpoint='shorten_api')
def shorten_api():
    api_key = request.headers.get('X-API-Key')
    if api_key:
        conn = db.get_db()
        user = core.get_user_by_api_key(conn, api_key)
        if not user:
            ip = request.remote_addr or 'unknown'
            if core.is_rate_limited(f"api_fail:{ip}", max_requests=10, window_seconds=600):
                return jsonify({'error': 'Too many invalid API key attempts'}), 429
            return jsonify({'error': 'Invalid API key'}), 401
        return _shorten_logic(user['id'])
    return _shorten_logic(None)

@api_bp.route('/shorten', methods=['POST'], endpoint='shorten_web')
def shorten_web():
    owner_id = session.get('user_id')
    if owner_id is not None:
        conn = db.get_db()
        if not conn.execute('SELECT id FROM users WHERE id = ?', (owner_id,)).fetchone():
            session.clear()
            owner_id = None
    return _shorten_logic(owner_id, enforce_guest_quota=True)

@api_bp.route('/api/stats/<code>', methods=['GET'], endpoint='api_stats')
@require_api_key
def api_stats(code):
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != g.api_user['id']:
        return jsonify({'error': 'Forbidden'}), 403

    clicks = conn.execute(
        'SELECT COUNT(*) AS count FROM clicks WHERE link_id = ?',
        (link['id'],)
    ).fetchone()['count']

    return jsonify({
        'code': link['code'],
        'original_url': link['original_url'],
        'created_at': link['created_at'],
        'safety_status': link['safety_status'],
        'clicks': clicks
    })

@api_bp.route('/api/<code>', methods=['DELETE'], endpoint='api_delete')
@require_api_key
def api_delete(code):
    conn = db.get_db()
    link = conn.execute('SELECT * FROM links WHERE code = ? COLLATE NOCASE', (code,)).fetchone()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    if link['owner_id'] != g.api_user['id']:
        return jsonify({'error': 'Forbidden'}), 403

    conn.execute('DELETE FROM links WHERE code = ? COLLATE NOCASE', (code,))
    conn.commit()
    _delete_screenshot_file(code)
    return jsonify({'message': 'Deleted successfully'})

@api_bp.route('/api/analytics', methods=['GET'], endpoint='api_analytics')
@require_api_key
def api_analytics():
    conn = db.get_db()
    limit_str = request.args.get('limit', '5')
    try:
        limit = int(limit_str)
        if limit < 1 or limit > 100:
            return jsonify({'error': 'Limit must be an integer between 1 and 100.'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Limit must be a valid integer.'}), 400

    top_links = conn.execute('''
        SELECT links.code, COUNT(clicks.id) AS click_count
        FROM links
        LEFT JOIN clicks ON links.id = clicks.link_id
        WHERE links.owner_id = ?
        GROUP BY links.id
        ORDER BY click_count DESC
        LIMIT ?
    ''', (g.api_user['id'], limit)).fetchall()

    return jsonify([
        {'code': row['code'], 'clicks': row['click_count']}
        for row in top_links
    ])
