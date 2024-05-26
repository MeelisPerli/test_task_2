from flask import Blueprint, jsonify
from db_utils import get_conn


api_development_bp = Blueprint('main', __name__)


@api_development_bp.route('/cve/<cve_id>')
def get_cve(cve_id):
    """
    This function returns the details of a CVE
    :param cve_id: CVE ID
    :return: JSON
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
        SELECT 
            id AS cve_id,
            published_at,
            last_modified_at,
            source_identifier,
            vuln_status
        FROM cve.cves
        WHERE id = %s
        """, (cve_id,))
        row = cur.fetchone()

    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        cur.close()
        conn.close()

    if not row or len(row) == 0:
        return jsonify({'error': 'CVE not found'})

    return jsonify({
        'cve_id': row[0],
        'published_at': row[1],
        'last_modified_at': row[2],
        'source_identifier': row[3],
        'vuln_status': row[4]}
    )