from flask import Blueprint

from db_utils import get_conn


analytical_questions_bp = Blueprint('analytics', __name__)

@analytical_questions_bp.route('/severity_distribution')
def severity_distribution():
    """
    This function returns the distribution of vulnerabilities by severity
    :return: JSON
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
        WITH 
        filtered AS (
            SELECT 
                i.base_severity,
                row_number() OVER (PARTITION BY i.cve_id ORDER BY version desc) = 1 AS flag_latest_version
            FROM cve.cves AS c
            LEFT JOIN cve.cve_impact AS i ON c.id = i.cve_id
            --  Making sure that we only use data as of 05-01-2024
            WHERE c.published_at < '2024-05-01' AND i.base_severity is not null
        ),

        final AS (
            SELECT 
                base_severity,
                count(*)
            FROM filtered
            WHERE flag_latest_version
            GROUP BY base_severity
            ORDER BY base_severity
        )
        SELECT * FROM final
        ;
        """)
        rows = cur.fetchall()

    except Exception as e:
        return {'error': str(e)}
    finally:
        cur.close()
        conn.close()

    return {
        'data': [{'severity': row[0], 'count': row[1]} for row in rows]
    }


@analytical_questions_bp.route('/worst_products')
def worst_products():
    """
    This function returns the top 10 products with the most known vulnerabilities
    :return: JSON
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT 
                SPLIT_PART(cpe23_uri, ':', 5) AS product,
                COUNT(*) AS number_of_known_vulnerabilities
                
            FROM cve.cves AS c
            LEFT JOIN cve.cve_cpe AS cp ON c.id = cp.cve_id
            --  Making sure that we only use data as of 05-01-2024
            WHERE c.published_at < '2024-05-01'
            GROUP BY 1
            ORDER BY 2 DESC
            limit 10
        ;
        """)
        rows = cur.fetchall()

    except Exception as e:
        return {'error': str(e)}
    finally:
        cur.close()
        conn.close()

    return {
        'data': [{'product': row[0], 'number_of_known_vulnerabilities': row[1]} for row in rows]
    }


@analytical_questions_bp.route('/highest_impact')
def highest_impact():
    """
    This function returns the top 10 CVEs with the highest impact score
    :return: JSON
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
                WITH 
                filtered_cves AS (
                    SELECT 
                        i.cve_id,
                        i.impact_score,
                        d.value AS description,
                        row_number() OVER (PARTITION BY i.cve_id ORDER BY version desc) = 1 AS flag_latest_version
                    FROM cve.cves AS c
                    LEFT JOIN cve.cve_impact AS i ON c.id = i.cve_id
                    LEFT JOIN cve.cve_description AS d ON c.id = d.cve_id
                    --  Making sure that we only use data as of 05-01-2024
                    WHERE c.published_at < '2024-05-01' AND d.lang = 'en'
                ),

                final AS (
                    SELECT 
                        cve_id,
                        description,
                        impact_score
                    FROM filtered_cves
                    WHERE flag_latest_version AND impact_score is not null
                    ORDER BY impact_score desc
                    LIMIT 10
                )
                SELECT * FROM final
                ;
                """)
        rows = cur.fetchall()

    except Exception as e:
        return {'error': str(e)}
    finally:
        cur.close()
        conn.close()

    return {
        'data': [{'cve': row[0], 'Description':row[1], 'Impact_score': row[2]} for row in rows]
    }


@analytical_questions_bp.route('/highest_exploitability')
def highest_exploitability():
    """
    This function returns the top 10 CVEs with the highest exploitability score
    :return: JSON
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
                WITH 
                filtered_cves AS (
                    SELECT 
                        i.cve_id,
                        i.exploitability_score,
                        d.value AS description,
                        row_number() OVER (PARTITION BY i.cve_id ORDER BY version desc) = 1 AS flag_latest_version
                    FROM cve.cves AS c
                    LEFT JOIN cve.cve_impact AS i ON c.id = i.cve_id
                    LEFT JOIN cve.cve_description AS d ON c.id = d.cve_id
                    --  Making sure that we only use data as of 05-01-2024
                    WHERE c.published_at < '2024-05-01' AND d.lang = 'en'
                ),

                final AS (
                    SELECT 
                        cve_id,
                        description,
                        exploitability_score
                    FROM filtered_cves
                    WHERE flag_latest_version AND exploitability_score is not null
                    ORDER BY exploitability_score desc
                    LIMIT 10
                )
                SELECT * FROM final
                ;
                """)
        rows = cur.fetchall()

    except Exception as e:
        return {'error': str(e)}
    finally:
        cur.close()
        conn.close()

    return {
        'data': [{'cve': row[0], 'description': row[1], 'exploitability_score': row[2]} for row in rows]
    }


@analytical_questions_bp.route('/top_attack_vectors')
def top_attack_vectors():
    """
    This function returns the top 10 attack vectors
    :return: JSON
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
                WITH 
                filtered_cves AS (
                    SELECT 
                        i.access_vector,
                        row_number() OVER (PARTITION BY i.cve_id ORDER BY version desc) = 1 AS flag_latest_version
                    FROM cve.cves AS c
                    LEFT JOIN cve.cve_impact AS i ON c.id = i.cve_id
                    --  Making sure that we only use data as of 05-01-2024
                    WHERE c.published_at < '2024-05-01'
                ),

                final AS (
                    SELECT 
                        access_vector,
                        count(*) AS count
                    FROM filtered
                    WHERE flag_latest_version
                    GROUP BY access_vector
                    ORDER BY exploitability_score desc
                    LIMIT 10
                )
                SELECT * FROM final
                ;
                """)
        rows = cur.fetchall()

    except Exception as e:
        return {'error': str(e)}
    finally:
        cur.close()
        conn.close()

    return {
        'data': [{'attack_vector': row[0], 'Usage': row[1]} for row in rows]
    }





