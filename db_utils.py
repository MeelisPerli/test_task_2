import logging
import os
import psycopg2


def get_conn():
    conn = psycopg2.connect(
        dbname=os.getenv('POSTGRES_DB_NAME'),
        user=os.getenv('POSTGRES_USERNAME'),
        password=os.getenv('POSTGRES_PASSWORD'),
        host=os.getenv('POSTGRES_HOST'),
        port=os.getenv('POSTGRES_PORT'),
    )
    return conn


def upsert_row(df, table_name, conn, primary_key: list = None):
    if primary_key is None:
        primary_key = []

    cur = conn.cursor()
    cur.execute("SET search_path TO cve;")
    try:
        for i, row in df.iterrows():
            query = f"""
                INSERT INTO {table_name} ({', '.join(df.columns)})
                VALUES ({', '.join(['%s'] * len(df.columns))})
                """
            if primary_key:
                query += f"""
                ON CONFLICT ({", ".join(primary_key)}) DO UPDATE
                SET {', '.join([f"{col}=EXCLUDED.{col}" for col in df.columns if col not in primary_key])};
                """
            try:
                cur.execute(query, tuple(row))
            except Exception as e:
                logging.error(f"Error inserting/updating row {row} in table {table_name}: {e}")
                logging.error(f"Query: {query}")
                raise e
        conn.commit()
    finally:
        cur.close()
