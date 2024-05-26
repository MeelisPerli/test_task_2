# Data Engineer Take-Home Assessment
### Solution by: Meelis Perli

## Used technologies
- Python 3.12.1
- PostgreSQL 16.1

## Setup
You can setup the required python packages by using the requirements.txt file. To do this, run the following command:
```
pip install -r requirements.txt
```

To be able to connect to the database, you need to have a postgres db set up and you also need to
have the following environment variables set:
- `POSTGRES_DB_NAME`
- `POSTGRES_USERNAME`
- `POSTGRES_PASSWORD`
- `POSTGRES_HOST`
- `POSTGRES_PORT`

### creating and filling the tables
To create the schema and tables, run the `CVE_schema_setup.sql` script in the `schema_scripts` folder. This 
will create the necessary schema, tables, triggers, functions and indexes.

To fill the tables with data, run the `CVE_data_collector.py` script in the `data_collection` folder. This takes some
but it will load all the data from the NVD feed into the tables you just created. 
Currently the script just loads the data once. Technically to update the data, the script can be run again,
but it is not recommended because another API should be used for that, for which I didn't have time to implement yet.

### Flask app
The Flask app can be started by running the `app.py` script in the `api` folder. This will start the app on `localhost:5000`.


## Design Choices

### Database
The database schema is designed to be as normalized as possible. The data is stored in 5 tables:
- `cve` - contains the CVEs
- `cve_impact` - contains the metrics for the CVEs and their impact
- `cve_references` - contains the references for the CVEs
- `cve_description` - contains the descriptions for the CVEs
- `cve_cpe` - contains the affected products for the CVEs

The tables are connected with foreign keys and indexes are created for the columns that are queried the most.
All tables also have a primary key, which is the `cve_id` column or a combination of columns. All tables also have
_created_at and _updated_at metadata columns. These can be used to track when the data was last updated in the database.
The _updated_at field for a row is updated whenever a row is updated.

## API
For the API, I chose to use Flask. Flask is a lightweight web framework that is easy to use.
The API is a RESTful API that returns JSON responses.

The app has the following endpoints:
### General Endpoints

- **CVE Details**
  - **Endpoint:** `/cve/<cve_id>`
  - **Method:** `GET`
  - **Description:** Returns the CVE with the given id
  - **Example Usage:** `localhost:5000/cve/CVE-1999-0249`
  - **Example Response:**
    ```json
    {
      "cve_id": "CVE-1999-0249",
      "last_modified_at": "2022-08-17T10:15:12.187",
      "published_at": "1997-01-01T05:00:00.000",
      "source_identifier": "cve@mitre.org",
      "vuln_status": "Modified"
    }
    ```


### Analytics endpoints:
- `/severity_distribution` - returns the affected products for the given CVE



