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

The Flask app can be started by running the `app.py` script in the `api` folder. This will start the app
on `localhost:5000`.

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

- **Severity Distribution**
    - **Endpoint:** `/severity_distribution`
    - **Method:** `GET`
    - **Description:** This endpoint returns the top 10 products with the most known vulnerabilities
    - **Example Usage:** `localhost:5000/severity_distribution`
    - **Example Response:**
      ```json
      {
      "data": [
        {
          "count": 9,
          "severity": "NONE"
        },
        {
          "count": 10216,
          "severity": "LOW"
        },
        {
          "count": 105240,
          "severity": "MEDIUM"
        },
        {
          "count": 92793,
          "severity": "HIGH"
        },
        {
          "count": 21852,
          "severity": "CRITICAL"
        }
      ]}
      ```

- **Worst Products**
    - **Endpoint:** `/worst_products`
    - **Method:** `GET`
    - **Description:** Returns 10 products with the most known vulnerabilities
    - **Example Usage:** `localhost:5000/worst_products`
    - **Example Response:**
      ```json 
      {
      "data": [
      {
        "number_of_known_vulnerabilities": 89751,
        "product": "linux_kernel"
      },
      {
        "number_of_known_vulnerabilities": 60481,
        "product": "ios"
      },
      {
        "number_of_known_vulnerabilities": 53956,
        "product": "junos"
      },
      {
        "number_of_known_vulnerabilities": 34296,
        "product": "firefox"
      },
      {
        "number_of_known_vulnerabilities": 33366,
        "product": "chrome"
      },
      {
        "number_of_known_vulnerabilities": 32621,
        "product": "android"
      },
      {
        "number_of_known_vulnerabilities": 27855,
        "product": "jre"
      },
      {
        "number_of_known_vulnerabilities": 23905,
        "product": "jdk"
      },
      {
        "number_of_known_vulnerabilities": 23782,
        "product": "windows_10"
      },
      {
        "number_of_known_vulnerabilities": 23418,
        "product": "mac_os_x"
      }
      ]}
      ```

- **Highest Impact Vulnerabilities**
    - **Endpoint:** `/highest_impact`
    - **Method:** `GET`
    - **parameters:**
        - `max_published_at` - the maximum published date for the CVEs
        - `min_published_at` - the minimum published date for the CVEs
    - **Description:** This endpoint returns the top 10 CVEs with the highest impact score
    - **Example Usage:** `localhost:5000/highest_impact`
    - **Example Response:**
      ```json
      {
      "data": [
      {
        "Description": "Buffer overflow in statd allows root privileges.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0018"
      },
      {
        "Description": "Unauthorized privileged access or denial of service via dtappgather program in CDE.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0014"
      },
      {
        "Description": "Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0002"
      },
      {
        "Description": "Denial of Service vulnerabilities in BIND 4.9 and BIND 8 Releases via CNAME record and zone transfer.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0011"
      },
      {
        "Description": "Buffer overflow in POP servers based on BSD/Qualcomm's qpopper allows remote attackers to gain root access using a long PASS command.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0006"
      },
      {
        "Description": "Execute commands as root via buffer overflow in Tooltalk database server (rpc.ttdbserverd).",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0003"
      },
      {
        "Description": "Buffer overflow in NIS+, in Sun's rpc.nisd program.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0008"
      },
      {
        "Description": "Inverse query buffer overflow in BIND 4.9 and BIND 8 Releases.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0009"
      },
      {
        "Description": "Arbitrary command execution via IMAP buffer overflow in authenticate command.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0005"
      },
      {
        "Description": "Local user gains root privileges via buffer overflow in rdist, via expstr() function.",
        "Impact_score": "10.0",
        "cve": "CVE-1999-0022"
      }
      ]}
      ```
- **Example Usage with params:** `localhost:5000/highest_impact?min_published_at=2020-01-01&max_published_at=2022-12-31`


- **Highest Exploitability Vulnerabilities**
    - **Endpoint:** `/highest_exploitability`
    - **Method:** `GET`
    - **parameters:**
        - `max_published_at` - the maximum published date for the CVEs
        - `min_published_at` - the minimum published date for the CVEs
    - **Description:** This endpoint returns the top 10 CVEs with the highest exploitability score
    - **Example Usage:** `localhost:5000/highest_exploitability`
    - **Example Response:**
      ```json
      {
      "data": [
      {
        "cve": "CVE-1999-0002",
        "description": "Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0003",
        "description": "Execute commands as root via buffer overflow in Tooltalk database server (rpc.ttdbserverd).",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0004",
        "description": "MIME buffer overflow in email clients, e.g. Solaris mailtool and Outlook.",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0005",
        "description": "Arbitrary command execution via IMAP buffer overflow in authenticate command.",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0006",
        "description": "Buffer overflow in POP servers based on BSD/Qualcomm's qpopper allows remote attackers to gain root access using a long PASS command.",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0007",
        "description": "Information from SSL-encrypted sessions via PKCS #1.",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0008",
        "description": "Buffer overflow in NIS+, in Sun's rpc.nisd program.",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0009",
        "description": "Inverse query buffer overflow in BIND 4.9 and BIND 8 Releases.",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0010",
        "description": "Denial of Service vulnerability in BIND 8 Releases via maliciously formatted DNS messages.",
        "exploitability_score": "10.0"
      },
      {
        "cve": "CVE-1999-0001",
        "description": "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.",
        "exploitability_score": "10.0"
      }
      ]}
      ```
- **Example Usage with params:
  ** `localhost:5000/highest_exploitability?min_published_at=2020-01-01&max_published_at=2022-12-31`


- **Top Attack Vectors**
    - **Endpoint:** `/top_attack_vectors`
    - **Method:** `GET`
    - **Description:** This endpoint returns the top attack vectors
    - **Example Usage:** `localhost:5000/top_attack_vectors`
    - **Example Response:**
      ```json
      {
      "data": [
      {
        "Usage": 175928,
        "attack_vector": "NETWORK"
      },
      {
        "Usage": 46206,
        "attack_vector": "LOCAL"
      },
      {
        "Usage": 6311,
        "attack_vector": "ADJACENT_NETWORK"
      },
      {
        "Usage": 1665,
        "attack_vector": "PHYSICAL"
      } ]}
      ```
