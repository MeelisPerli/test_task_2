from db_utils import get_conn


def create_or_replace_modified_at_trigger(cur):
    cur.execute("""
    CREATE OR REPLACE FUNCTION update_modified_at_column()
    RETURNS TRIGGER AS $$
    BEGIN
       NEW._modified_at = NOW();
       RETURN NEW;
    END;
    $$ language 'plpgsql';
    """)


def create_or_replace_cve(cur):
    cur.execute("""DROP TYPE IF EXISTS vuln_status_enum CASCADE""")
    cur.execute("""
    CREATE TYPE vuln_status_enum AS ENUM (
        'Analyzed',
        'Awaiting Analysis',
        'Modified',
        'Received',
        'Rejected',
        'Undergoing Analysis'
    );
    """)

    # Create the main fact table
    cur.execute("""DROP TABLE IF EXISTS cves CASCADE;""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id VARCHAR(20) PRIMARY KEY,
        published_at TIMESTAMPTZ NOT NULL,
        last_modified_at TIMESTAMPTZ NOT NULL,
        source_identifier TEXT NOT NULL,
        vuln_status vuln_status_enum NOT NULL,
        _created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        _modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TRIGGER update_cves_modtime
    BEFORE UPDATE ON cves
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_at_column();
    """)

    # create indexes
    cur.execute("CREATE INDEX idx_cves_id ON cves (id);")
    cur.execute("CREATE INDEX idx_cves_published_at ON cves (published_at);")


def create_or_replace_cve_impact(cur):
    # Create enums for cve_imact
    cur.execute("""
    DROP TYPE IF EXISTS base_severity_enum CASCADE;
    DROP TYPE IF EXISTS access_vector_enum CASCADE;
    DROP TYPE IF EXISTS access_complexity_enum CASCADE;
    DROP TYPE IF EXISTS authentication_enum CASCADE;
    DROP TYPE IF EXISTS confidentiality_impact_enum CASCADE;
    DROP TYPE IF EXISTS integrity_impact_enum CASCADE;
    DROP TYPE IF EXISTS availability_impact_enum CASCADE;
    """)

    cur.execute("""
    CREATE TYPE base_severity_enum AS ENUM (
        'NONE',
        'LOW', 
        'MEDIUM', 
        'HIGH', 
        'CRITICAL'
    );
    
    CREATE TYPE access_vector_enum AS ENUM (
        'ADJACENT_NETWORK',
        'LOCAL',
        'NETWORK',
        'PHYSICAL'
    );
    
    CREATE TYPE access_complexity_enum AS ENUM (
        'LOW', 
        'MEDIUM', 
        'HIGH'
    );
    
    CREATE TYPE authentication_enum AS ENUM (
        'MULTIPLE', 
        'HIGH',
        'NONE', 
        'SINGLE',
        'LOW'
    );
    
    CREATE TYPE confidentiality_impact_enum AS ENUM (
        'COMPLETE', 
        'NONE', 
        'PARTIAL',
        'HIGH',
        'LOW'
    );
    
    
    CREATE TYPE integrity_impact_enum AS ENUM (
        'COMPLETE', 
        'NONE', 
        'PARTIAL',
        'HIGH',
        'LOW'
        
    );
    
    CREATE TYPE availability_impact_enum AS ENUM (
        'COMPLETE', 
        'NONE', 
        'PARTIAL',
        'HIGH',
        'LOW'
    );
    """)

    # Create the impact table
    cur.execute("""DROP TABLE IF EXISTS cve_impact CASCADE;""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cve_impact (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) NOT NULL,
        version DECIMAL NOT NULL,
        base_score DECIMAL NOT NULL,
        base_severity base_severity_enum,
        vector_string TEXT NOT NULL,
        access_vector access_vector_enum,
        access_complexity access_complexity_enum,
        authentication authentication_enum,
        confidentiality_impact confidentiality_impact_enum,
        integrity_impact integrity_impact_enum,
        availability_impact availability_impact_enum,
        exploitability_score DECIMAL,
        impact_score DECIMAL,
        ac_insuf_info BOOLEAN,
        obtain_all_privilege BOOLEAN,
        obtain_user_privilege BOOLEAN,
        obtain_other_privilege BOOLEAN,
        user_interaction_required BOOLEAN,
        _created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        _modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT cve_impact_unique UNIQUE (cve_id, version),
        FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
    );
    
    CREATE TRIGGER update_cve_impact_modtime
    BEFORE UPDATE ON cve_impact
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_at_column();
    """)

    # Add indexes
    cur.execute("CREATE INDEX idx_cve_impact_base_severity ON cve_impact (base_severity);")
    cur.execute("CREATE INDEX idx_cve_impact_impact_score ON cve_impact (impact_score);")
    cur.execute("CREATE INDEX idx_cve_impact_exploitability_score ON cve_impact (exploitability_score);")
    cur.execute("CREATE INDEX idx_cve_impact_access_vector ON cve_impact (access_vector);")


def create_or_replace_cve_reference(cur):
    # Create the references table
    cur.execute("""DROP TABLE IF EXISTS cve_references CASCADE;""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cve_references (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) NOT NULL,
        url TEXT NOT NULL,
        source TEXT,
        _created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        _modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT cve_references_unique UNIQUE (cve_id, url),
        FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
    );
    
    CREATE TRIGGER update_cve_references_modtime
    BEFORE UPDATE ON cve_references
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_at_column();
    """)


def create_or_replace_cve_description(cur):
    # Create the description table
    cur.execute("""DROP TABLE IF EXISTS cve_description CASCADE;""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cve_description (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) NOT NULL,
        lang TEXT NOT NULL,
        value TEXT NOT NULL,
        _created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        _modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT cve_description_unique UNIQUE (cve_id, lang),
        FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
    );
    
    CREATE TRIGGER update_cve_description_modtime
    BEFORE UPDATE ON cve_description
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_at_column();
    """)


def create_or_replace_cve_cpe(cur):
    # Create CVE CPE table
    cur.execute("""DROP TABLE IF EXISTS cve_cpe CASCADE;""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cve_cpe (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) NOT NULL,
        match_criteria_id VARCHAR(50) NOT NULL,
        flag_vulnerable BOOLEAN NOT NULL,
        cpe23_uri TEXT NOT NULL,
        _created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        _modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT cve_cpe_unique UNIQUE (cve_id, match_criteria_id),
        FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
    );
    
    CREATE TRIGGER update_cve_cpe_modtime
    BEFORE UPDATE ON cve_cpe
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_at_column();
    """)

    # add index
    cur.execute("CREATE INDEX idx_cve_cpe_cpe23_uri ON cve_cpe (cpe23_uri);")


if __name__ == '__main__':
    # Connect to the PostgreSQL database
    conn = get_conn()
    cur = conn.cursor()

    # Set the schema where you want to create your tables
    cur.execute("CREATE SCHEMA IF NOT EXISTS cve;")
    cur.execute("SET search_path TO cve;")


    # Create the tables
    create_or_replace_modified_at_trigger(cur)
    create_or_replace_cve(cur)
    create_or_replace_cve_impact(cur)
    create_or_replace_cve_reference(cur)
    create_or_replace_cve_description(cur)
    create_or_replace_cve_cpe(cur)

    conn.commit()
    cur.close()
    conn.close()
