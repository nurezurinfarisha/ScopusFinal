from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash, Response
import mysql.connector
import time
import requests
import csv
import logging
import os
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
from flask_session import Session
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from mysql.connector import errorcode
from mysql.connector import pooling
from io import StringIO
from flask import render_template, make_response
import pdfkit

app = Flask(__name__)
app.secret_key = '187b09147f02bec0feaadd6e54e8c780'

# Set up logging to print activity details
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logging.basicConfig(filename='papers_insertion.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')
                    
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

dbconfig = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "scopus_db",
    "pool_name": "mypool",  # Name of the connection pool
    "pool_size": 5,         # Number of connections in the pool
    "connection_timeout": 300  # Timeout for idle connections
}

# Initialize connection pool
db = pooling.MySQLConnectionPool(**dbconfig)

def get_db_connection():
    """Get a connection from the pool."""
    try:
        # Get a connection from the pool
        return db.get_connection()
    except mysql.connector.errors.OperationalError as e:
        logging.error(f"Error getting DB connection from pool: {e}")
        return None

# === 🔍 Scopus API Config ===
SCOPUS_SEARCH_URL = "https://api.elsevier.com/content/search/scopus"
SCOPUS_ABSTRACT_URL = "https://api.elsevier.com/content/abstract/scopus_id/"
SCOPUS_AFFILIATION_URL = "https://api.elsevier.com/content/affiliation/"

@app.route('/admin_login', methods=['POST'])
def admin_login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for('index'))

    # Get a connection from the pool
    connection = get_db_connection()  # Use the connection pool's connection
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        flash("Failed to get a DB connection. Please try again.", "error")
        return redirect(url_for('index'))

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM admin_users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = user['username']
            flash(f"Welcome, {user['username']}!", "success")
            return redirect(url_for('overview'))
        else:
            flash("Invalid username or password.", "error")
            return redirect(url_for('index'))

    except mysql.connector.Error as e:
        logging.error(f"Database error during admin login: {e}")
        flash("Database error occurred. Please try again.", "error")
        return redirect(url_for('index'))

    finally:
        cursor.close()  # Ensure the cursor is closed
        connection.close()  # Release the connection back to the pool

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not (username and email and password and confirm_password):
            flash("All fields are required.", "error")
            return redirect(url_for('admin_register'))
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('admin_register'))

        password_hash = generate_password_hash(password)

        # Get a connection from the pool
        connection = get_db_connection()  # Use the connection pool's connection
        if connection is None:
            logging.error("Failed to get a DB connection from the pool.")
            flash("Failed to get a DB connection. Please try again.", "error")
            return redirect(url_for('admin_register'))

        cursor = connection.cursor()

        try:
            cursor.execute("INSERT INTO admin_users (username, email, password_hash) VALUES (%s, %s, %s)",
                           (username, email, password_hash))
            connection.commit()
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for('index'))
        except mysql.connector.IntegrityError:
            flash("Username or email already exists.", "error")
            return redirect(url_for('admin_register'))
        except mysql.connector.Error as e:
            logging.error(f"Database error during admin registration: {e}")
            flash("An error occurred while creating the account. Please try again.", "error")
            return redirect(url_for('admin_register'))
        finally:
            cursor.close()  # Ensure the cursor is closed
            connection.close()  # Release the connection back to the pool

    # GET request: show registration page
    return render_template('admin_register.html')

@app.route('/admin_forgot_password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("Please enter your email address.", "error")
            return redirect(url_for('admin_forgot_password'))

        # Get a connection from the pool
        connection = get_db_connection()  # Use the connection pool's connection
        if connection is None:
            logging.error("Failed to get a DB connection from the pool.")
            flash("Failed to get a DB connection. Please try again.", "error")
            return redirect(url_for('admin_forgot_password'))

        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("SELECT * FROM admin_users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                # For simplicity, just flash message. In real app, send reset email.
                flash(f"Password reset instructions sent to {email} (not implemented).", "info")
            else:
                flash("Email address not found.", "error")

        except mysql.connector.Error as e:
            logging.error(f"Database error during password reset: {e}")
            flash("An error occurred while processing your request. Please try again.", "error")

        finally:
            cursor.close()  # Ensure the cursor is closed
            connection.close()  # Release the connection back to the pool

        return redirect(url_for('index'))

    return render_template('admin_forgot_password.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))

def get_current_api_key():
    # Get a connection from the pool
    connection = get_db_connection()  # Use the connection pool's connection
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        return None  # Fallback if connection cannot be fetched

    cursor = connection.cursor()

    try:
        cursor.execute("SELECT api_key FROM api_keys ORDER BY created_at DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else None
    except mysql.connector.Error as err:
        logging.error(f"Error fetching API key: {err}")
        return None
    finally:
        cursor.close()  # Ensure the cursor is closed
        connection.close()  # Release the connection back to the pool

def update_api_key_last_used(api_key):
    # Get a connection from the pool
    connection = get_db_connection()  # Use the connection pool's connection
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        return

    cursor = connection.cursor()

    try:
        cursor.execute("UPDATE api_keys SET last_used = %s WHERE api_key = %s", (datetime.now(), api_key))
        connection.commit()
    except mysql.connector.Error as err:
        logging.error(f"Error updating last used API key: {err}")
    finally:
        cursor.close()  # Ensure the cursor is closed
        connection.close()  # Release the connection back to the pool

def add_new_api_key(new_key):
    # Get a connection from the pool
    connection = get_db_connection()  # Use the connection pool's connection
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        return

    cursor = connection.cursor()

    try:
        cursor.execute("INSERT INTO api_keys (api_key) VALUES (%s)", (new_key,))
        connection.commit()
    except mysql.connector.Error as err:
        logging.error(f"Error adding new API key: {err}")
    finally:
        cursor.close()  # Ensure the cursor is closed
        connection.close()  # Release the connection back to the pool


@app.route('/admin/api_keys')
def admin_api_keys():
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('index'))

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM api_keys ORDER BY created_at DESC")
    keys = cursor.fetchall()
    cursor.close()

    return render_template('admin_api_keys.html', api_keys=keys)


@app.route('/admin/api_keys/update', methods=['POST'])
def admin_api_key_update():
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('index'))

    new_key = request.form.get('new_api_key', '').strip()
    if not new_key:
        flash("API key cannot be empty.", "error")
        return redirect(url_for('admin_api_keys'))

    add_new_api_key(new_key)
    flash("API key updated successfully.", "success")
    return redirect(url_for('admin_api_keys'))

def exponential_backoff(retries):
    # Use exponential backoff strategy (e.g., 1s, 2s, 4s, 8s, etc.)
    wait_time = 2 ** retries  # Exponential backoff
    logging.warning(f"⚠️ Retrying in {wait_time} seconds...")
    time.sleep(wait_time)

def load_lecturer_data():
    lecturers = set()
    
    # Get a connection from the pool
    connection = get_db_connection()  # Use the connection pool's connection
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        return lecturers  # Return an empty set if connection fails

    cursor = connection.cursor(dictionary=True)  # Use dictionary=True to fetch rows as dictionaries
    
    try:
        # Query the database for indexed names
        cursor.execute("SELECT `indexed_name` FROM lecturer")
        rows = cursor.fetchall()

        # Add indexed names to the set
        for row in rows:
            indexed = row['indexed_name'].strip().lower()  # Now row is a dictionary
            if indexed:
                lecturers.add(indexed)

    except mysql.connector.Error as e:
        logging.error(f"Error loading lecturer data: {e}")
    
    finally:
        cursor.close()  # Ensure the cursor is closed
        connection.close()  # Release the connection back to the pool

    return lecturers

# Load lecturer data (this will call the function with connection pooling)
lecturers = load_lecturer_data()



def categorize_author(author_name, lecturers):
    author_name = author_name.strip().lower()
    return "Staff" if author_name in lecturers else "Student"

def categorize_authors_in_paper(paper, lecturers):
    paper = paper.copy()
    paper['authors_category'] = []  # Ensure this is always initialized

    authors = paper.get('Authors')
    if not authors:
        return paper  # Skip if no author info

    for author in authors.split(", "):
        if author.strip() in ("", "N/A"):
            continue
        category = categorize_author(author, lecturers)
        paper['authors_category'].append(category)

    # If no authors are categorized, add a default category
    if not paper['authors_category']:
        paper['authors_category'] = ['Unknown']

    return paper
@app.route('/filter_by_author_type/<string:author_type>')
def filter_by_author_type(author_type):
    scopus_ids = session.get('scopus_ids', [])
    if not scopus_ids:
        flash("No search results to filter. Please search first.", "warning")
        return redirect(url_for('index'))

    # Get a connection from the pool
    connection = get_db_connection()
    if connection is None:
        flash("Failed to get a DB connection. Please try again.", "error")
        return redirect(url_for('index'))

    # Create cursor from the connection
    cursor = connection.cursor(dictionary=True)
    format_strings = ','.join(['%s'] * len(scopus_ids))
    cursor.execute(f"SELECT * FROM papers WHERE SCOPUS_ID IN ({format_strings})", tuple(scopus_ids))
    papers = cursor.fetchall()
    cursor.close()

    categorized_papers = []
    for paper in papers:
        categorized_paper = categorize_authors_in_paper(paper, lecturers)
        authors_with_category = list(zip(
            categorized_paper['Authors'].split(', '),
            categorized_paper['authors_category']
        ))
        categorized_paper['authors_with_category'] = authors_with_category
        categorized_papers.append(categorized_paper)

    # ✅ Count BEFORE filtering
    staff_count = sum("Staff" in p['authors_category'] for p in categorized_papers)
    student_count = sum("Student" in p['authors_category'] for p in categorized_papers)

    # Filter the papers based on author_type
    if author_type == "staff":
        filtered = [p for p in categorized_papers if "Staff" in p['authors_category']]
        for p in filtered:
            p['display_authors'] = [name for name, _ in p['authors_with_category']]

    elif author_type == "student":
        filtered = [p for p in categorized_papers if all(cat == "Student" for cat in p['authors_category'])]
        for p in filtered:
            p['display_authors'] = [name for name, cat in p['authors_with_category'] if cat == "Student"]

    else:
        filtered = categorized_papers
        for p in filtered:
            p['display_authors'] = [name for name, _ in p['authors_with_category']]

    total_results = len(filtered)

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of results per page
    total_pages = (total_results // per_page) + (1 if total_results % per_page > 0 else 0)

    # Slice the filtered list for pagination
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    paginated_results = filtered[start_index:end_index]

    # Return the results with pagination
    return render_template(
        'result.html',
        results=paginated_results,
        query=session.get('query', ''),
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        sort_by='newest',
        staff_count=staff_count,
        student_count=student_count,
        total_results=total_results
    )


@app.route('/')
def index():
    return render_template('index.html')

def get_affiliation_id(affiliation_name):
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database.")
        return None

    url = "https://api.elsevier.com/content/search/affiliation"
    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}
    params = {"query": f"affil({affiliation_name})", "count": 1}

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        results = response.json().get("search-results", {}).get("entry", [])
        if results:
            return results[0].get("dc:identifier", "").split(":")[-1]  # Get ID part
    else:
        logging.error(f"Failed to fetch affiliation ID for '{affiliation_name}', status code: {response.status_code}")
    return None


# Example logging in the Scopus data fetching function
def get_scopus_data(query):
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database!")
        return {"search-results": {"entry": []}}

    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}
    all_entries = []
    start = 0
    count = 50

    params = {"query": query, "count": count, "start": start}
    logging.info(f"🔍 Sending request to Scopus API with query: {query} | start={start} count={count}")
    response = requests.get(SCOPUS_SEARCH_URL, headers=headers, params=params)

    update_api_key_last_used(api_key)

    if response.status_code != 200:
        logging.error(f"⚠️ API Error {response.status_code}: {response.text}")
        return {"search-results": {"entry": []}}

    data = response.json()
    total_results = int(data.get("search-results", {}).get("opensearch:totalResults", 0))
    logging.info(f"📦 Total results to fetch: {total_results}")

    if total_results == 0:
        return {"search-results": {"entry": []}, "no_results": True}

    entries = data.get("search-results", {}).get("entry", [])
    all_entries.extend(entries)

    while len(all_entries) < total_results:
        start += count
        params["start"] = start
        logging.info(f"🔄 Fetching more data from Scopus API: start={start}, count={count}")
        response = requests.get(SCOPUS_SEARCH_URL, headers=headers, params=params)
        update_api_key_last_used(api_key)

        if response.status_code != 200:
            logging.error(f"⚠️ Failed at start={start}, status={response.status_code}")
            break

        entries = response.json().get("search-results", {}).get("entry", [])
        if not entries:
            logging.info("✅ No more results found.")
            break

        all_entries.extend(entries)
        logging.info(f"🔄 Fetched {len(all_entries)} of {total_results}...")

        time.sleep(1)

    logging.info(f"✅ Fetched a total of {len(all_entries)} entries.")
    return {"search-results": {"entry": all_entries}}

def get_abstract(scopus_id):
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database!")
        return "N/A"

    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}
    params = {"view": "FULL"}

    for attempt in range(3):  # Retry 3 times with exponential backoff
        try:
            response = requests.get(SCOPUS_ABSTRACT_URL + scopus_id, headers=headers, params=params)
            update_api_key_last_used(api_key)

            if response.status_code == 200:
                coredata = response.json().get("abstracts-retrieval-response", {}).get("coredata", {})
                abstract = coredata.get("dc:description")
                if not abstract:
                    logging.warning(f"⚠️ No abstract found for SCOPUS_ID {scopus_id}")
                    return "N/A"
                return abstract
            elif response.status_code == 429:  # Too Many Requests (rate limit reached)
                exponential_backoff(attempt)
            else:
                logging.warning(f"⚠️ Failed to fetch abstract for {scopus_id} | Status: {response.status_code}")
                break
        except Exception as e:
            logging.error(f"❌ Error during abstract fetch for {scopus_id}: {e}")
            exponential_backoff(attempt)

    return "N/A"

def get_subject_classification(scopus_id):
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database!")
        return "N/A"

    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}
    params = {"view": "FULL"}

    for attempt in range(3):
        try:
            response = requests.get(SCOPUS_ABSTRACT_URL + scopus_id, headers=headers, params=params)
            update_api_key_last_used(api_key)

            if response.status_code == 200:
                subjects = response.json().get("abstracts-retrieval-response", {}).get("subject-areas", {}).get("subject-area", [])
                if not subjects:
                    logging.warning(f"⚠️ No subject classification found for SCOPUS_ID {scopus_id}")
                    return "N/A"

                if isinstance(subjects, list):
                    return ", ".join(s.get("$", "N/A") for s in subjects)
                elif isinstance(subjects, dict):
                    return subjects.get("$", "N/A")
            else:
                logging.warning(f"⚠️ Attempt {attempt+1}: Failed subject classification for {scopus_id} | Status: {response.status_code}")
        except Exception as e:
            logging.error(f"❌ Error during subject classification fetch for {scopus_id}: {e}")
        time.sleep(2 ** attempt)

    return "N/A"


def list_to_str(value):
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    elif value is None:
        return ""
    return str(value)

def get_authors(scopus_id):
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database!")
        return [], [], []

    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}
    params = {"view": "FULL"}

    for attempt in range(3):  # Retry 3 times with exponential backoff
        try:
            response = requests.get(SCOPUS_ABSTRACT_URL + scopus_id, headers=headers, params=params)
            update_api_key_last_used(api_key)

            if response.status_code == 200:
                data = response.json().get("abstracts-retrieval-response", {})
                authors_data = data.get("authors", {}).get("author", [])
                if not authors_data:
                    logging.warning(f"⚠️ No author data found for SCOPUS_ID {scopus_id}")
                    return [], [], []

                names, ids, affiliations = [], [], []
                for author in authors_data:
                    names.append(author.get("ce:indexed-name", "N/A"))
                    ids.append(author.get("@auid", "N/A"))
                    affils = author.get("affiliation", [])
                    if isinstance(affils, list):
                        aff_ids = [a.get("@id", "N/A") for a in affils]
                    else:
                        aff_ids = [affils.get("@id", "N/A")]
                    affiliations.append("; ".join(aff_ids))

                return names, ids, affiliations
            elif response.status_code == 429:  # Rate limit error
                exponential_backoff(attempt)
            else:
                logging.warning(f"⚠️ Failed to fetch authors for {scopus_id} | Status: {response.status_code}")
                break
        except Exception as e:
            logging.error(f"❌ Error during author fetch for {scopus_id}: {e}")
            exponential_backoff(attempt)

    return [], [], []

def extract_paper_details(data):
    papers = []
    if not data or "search-results" not in data:
        return papers

    for entry in data["search-results"].get("entry", []):
        scopus_id = entry.get("dc:identifier", "").split(":")[-1]

        # Extract authors and other metadata (e.g., abstract, subjects)
        authors, author_ids, author_affiliations = get_authors(scopus_id)
        abstract = get_abstract(scopus_id)
        subjects = get_subject_classification(scopus_id)

        # Handle affiliation extraction
        affiliations = entry.get("affiliation", [])
        affil_names, affil_cities, affil_countries = [], [], []

        if isinstance(affiliations, list):
            for affil in affiliations:
                affil_names.append(affil.get("affilname", "N/A"))
                affil_cities.append(affil.get("affiliation-city", "N/A"))
                affil_countries.append(affil.get("affiliation-country", "N/A"))
        elif isinstance(affiliations, dict):
            affil_names.append(affiliations.get("affilname", "N/A"))
            affil_cities.append(affiliations.get("affiliation-city", "N/A"))
            affil_countries.append(affiliations.get("affiliation-country", "N/A"))
        else:
            affil_names.append("N/A")
            affil_cities.append("N/A")
            affil_countries.append("N/A")

        # Prepare paper details
        paper = {
            "SCOPUS_ID": scopus_id,
            "EID": entry.get("eid", "N/A"),
            "Title": entry.get("dc:title", "N/A"),
            "Authors": authors,
            "Author IDs": author_ids,
            "Author Affiliations": author_affiliations,
            "Creators": entry.get("dc:creator", "N/A"),
            "Publication Name": entry.get("prism:publicationName", "N/A"),
            "eISSN": entry.get("prism:eIssn", "N/A"),
            "Volume": entry.get("prism:volume", "N/A"),
            "Page Range": entry.get("prism:pageRange", "N/A"),
            "Cover Date": entry.get("prism:coverDate", "N/A"),
            "DOI": entry.get("prism:doi", "N/A"),
            "Cited By Count": entry.get("citedby-count", "N/A"),
            "Aggregation Type": entry.get("prism:aggregationType", "N/A"),
            "Subtype": entry.get("subtype", "N/A"),
            "Subtype Description": entry.get("subtypeDescription", "N/A"),
            "Source ID": entry.get("source-id", "N/A"),
            "Open Access": entry.get("openaccess", "N/A"),
            "URL": entry.get("prism:url", "N/A"),
            "Abstract": abstract,
            "Subject Classification": subjects,
            "Affiliation Names": " | ".join(str(name or "N/A") for name in affil_names),
            "Affiliation Cities": " | ".join(str(city or "N/A") for city in affil_cities),
            "Affiliation Countries": " | ".join(str(country or "N/A") for country in affil_countries),
        }

        papers.append(paper)

        # Adding a delay for API rate limiting; consider using batch processing if possible
        time.sleep(1)

    return papers


def safe(value):
    return value if value not in [None, ""] else "N/A"

def find_affiliation_in_db(affiliation, valid_aff_ids):
    """
    This function checks if any of the given affiliation IDs exist in the database.
    If found, returns the matching affiliation ID, otherwise returns None.
    """
    connection = get_db_connection()  # Get connection from the pool
    if not connection:
        logging.error("Could not get database connection from pool.")
        return None

    try:
        cursor = connection.cursor(dictionary=True)

        # Query to find the Author Affiliations that match any of the valid affiliation IDs
        aff_conditions = " OR ".join([f"Author Affiliations LIKE %s" for _ in valid_aff_ids])
        params = [f"%{aff_id}%" for aff_id in valid_aff_ids]

        cursor.execute(f"SELECT DISTINCT Author Affiliations FROM papers WHERE {aff_conditions}", tuple(params))
        rows = cursor.fetchall()

        # Check for the matching affiliation
        for row in rows:
            aff_ids = [i.strip() for i in (row['Author Affiliations'] or '').split(",")]
            for aff_id in valid_aff_ids:
                if aff_id in aff_ids:
                    return aff_id

    except Exception as e:
        logging.error(f"Error during affiliation check: {e}")
        return None
    finally:
        # Ensure the connection is released back to the pool
        connection.close()

    return None


@app.route('/search', methods=['POST'])
def search():
    query = request.form.get('query')
    filters = []

    # User input filters
    author = request.form.get('author_value')
    affiliation = request.form.get('affiliations_value')
    year = request.form.get('publication_year_value')
    scopus_id = request.form.get('scopus_id_value')
    selected_filters = request.form.getlist('filter[]')

    if not query.strip() and not any([author, affiliation, year, scopus_id] + selected_filters):
        flash("Please insert a query or select a filter to proceed.", "warning")
        return redirect(url_for('index'))  # Redirect back to the index page

    query_clean = query.strip().lower() if query else ''
    query_search = f"%{query_clean}%"

    # Build Scopus query
    if query_clean:
        query = f'TITLE("{query_clean}")'
    else:
        query = ''

    if 'author' in selected_filters and author:
        filters.append(f'AUTH("{author}")')

    # Check for multiple affiliation IDs in the database first if UUM (or similar) is selected
    matched_aff_id = None
    if 'affiliations' in selected_filters and affiliation:
        affiliation_lower = affiliation.strip().lower()

        # Define the list of valid affiliation IDs (for example, UUM-related IDs)
        valid_aff_ids = ["60002763", "60212344", "60228314", "60228313", "60212346"]

        # Check if the affiliation corresponds to UUM or a similar condition
        if affiliation_lower == "uum" or affiliation_lower == "university utara malaysia" or affiliation_lower == "universiti utara malaysia":
            # Use the new function to check the database for multiple IDs
            matched_aff_id = find_affiliation_in_db(affiliation, valid_aff_ids)

            # If no match is found in DB, fall back to Scopus API for "60002763"
            if not matched_aff_id:
                logging.info(f"No match in DB for '{affiliation}'. Querying Scopus for ID 60002763.")
                aff_id = get_affiliation_id("60002763")  # Only query Scopus for this ID
                if aff_id:
                    filters.append(f'AF-ID({aff_id})')
                    matched_aff_id = aff_id
                else:
                    logging.warning(f"⚠️ No affiliation ID found for: {affiliation}")

            # If a matched affiliation ID is found, add to filters
            if matched_aff_id:
                filters.append(f'AF-ID({matched_aff_id})')
    if 'publication_year' in selected_filters and year:
        filters.append(f'PUBYEAR IS {year}')
    if 'scopus_id' in selected_filters and scopus_id:
        filters.append(f'SCOPUS_ID:{scopus_id}')
    if filters:
        if query:
            query += " AND " + " AND ".join(filters)
        else:
            query = " AND ".join(filters)

    logging.info(f"Search Query: {query}")

    # === Search Local DB ===
    connection = get_db_connection()  # Get connection from the pool
    if not connection:
        flash("Error: Could not get a DB connection.", "error")
        return redirect(url_for('index'))

    try:
        cursor = connection.cursor(dictionary=True)
        sql = "SELECT * FROM papers WHERE LOWER(TRIM(Title)) LIKE %s"
        params = [query_search]

        if 'author' in selected_filters and author:
            sql += " AND LOWER(Authors) LIKE %s"
            params.append(f"%{author.lower()}%")
        if matched_aff_id:
            # Check against all valid_aff_ids in DB
            aff_conditions = " OR ".join(["`Author Affiliations` LIKE %s" for _ in valid_aff_ids])
            sql += f" AND ({aff_conditions})"
            params.extend([f"%{aff_id}%" for aff_id in valid_aff_ids])
        if 'publication_year' in selected_filters and year:
            sql += " AND `Cover Date` LIKE %s"
            params.append(f"{year}%")
        if 'scopus_id' in selected_filters and scopus_id:
            sql += " AND SCOPUS_ID = %s"
            params.append(scopus_id)

        cursor.execute(sql, tuple(params))
        existing_papers = cursor.fetchall()
        cursor.close()

        if existing_papers:
            logging.info("🔍 Found results in database for query with filters.")
            flash("Data fetched successfully for selected", "success")

            categorized_papers = []
            # Initialize counts for each year
            year_counts = {}

            for paper in existing_papers:
                paper = categorize_authors_in_paper(paper, lecturers)
                categorized_papers.append(paper)

                year = paper['Cover Date'].year  # Get the year from the datetime object
                if year not in year_counts:
                    year_counts[year] = {'staff_count': 0, 'student_count': 0}

                # Increment counts based on author category
                if "Staff" in paper["authors_category"]:
                    year_counts[year]['staff_count'] += 1
                else:
                    year_counts[year]['student_count'] += 1

            session['scopus_ids'] = [paper['SCOPUS_ID'] for paper in categorized_papers]
            session['query'] = query
            session.modified = True

            # Update or insert data for each year in the publication_counts table
            cursor = connection.cursor()
            for year, counts in year_counts.items():
                cursor.execute("""
                    INSERT INTO publication_counts (year, staff_count, student_count, last_updated)
                    VALUES (%s, %s, %s, NOW())
                    ON DUPLICATE KEY UPDATE staff_count = %s, student_count = %s, last_updated = NOW()
                """, (year, counts['staff_count'], counts['student_count'], counts['staff_count'], counts['student_count']))
            connection.commit()
            cursor.close()

            # Redirect to result page after flash message
            return redirect(url_for('result', page=1, sort_by='newest'))

    except Exception as e:
        logging.error(f"Database error during search: {e}")
        flash("An error occurred during the search. Please try again later.", "error")
        return redirect(url_for('index'))

    finally:
        # Ensure the connection is released back to the pool
        connection.close()

    # === Scopus Fallback ===
    logging.info(f"🚀 Data not found in database. Querying Scopus API for: {query}")
    scopus_data = get_scopus_data(query)
    paper_details = extract_paper_details(scopus_data)

    # Normalize authors field to string for rendering
    for paper in paper_details:
        if isinstance(paper.get("Authors"), list):
            paper["Authors"] = ", ".join(paper["Authors"])

    # Proper categorization
    paper_details = [categorize_authors_in_paper(p, lecturers) for p in paper_details]

    staff_count = sum('Staff' in p.get('authors_category', []) for p in paper_details)
    student_count = sum('Student' in p.get('authors_category', []) for p in paper_details)

    if not paper_details:
        # ❌ No data from Scopus
        flash("Data not found. Please check your input.", "error")
        return redirect(url_for('index'))

    # Save to DB
    connection = get_db_connection()  # Get connection from the pool
    try:
        cursor = connection.cursor()
        for paper in paper_details:
            scopus_id = safe(paper['SCOPUS_ID'])
            if scopus_id == "N/A":
                logging.warning(f"⚠️ Skipping paper with missing SCOPUS_ID.")
                continue

            cursor.execute("SELECT SCOPUS_ID FROM papers WHERE SCOPUS_ID = %s", (scopus_id,))
            if cursor.fetchone():
                logging.warning(f"⚠️ Skipping duplicate SCOPUS_ID: {scopus_id}")
                continue

            cursor.execute("""INSERT INTO papers (
                `SCOPUS_ID`, `EID`, `Title`, `Authors`, `Author IDs`, `Author Affiliations`,
                `Creators`, `Publication Name`, `eISSN`, `Volume`, `Page Range`, `Cover Date`,
                `DOI`, `Cited By Count`, `Aggregation Type`, `Subtype`, `Subtype Description`,
                `Source ID`, `Open Access`, `URL`, `Abstract`, `Subject Classification`,
                `Affiliation Names`, `Affiliation Cities`, `Affiliation Countries`
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", (
                scopus_id, safe(paper['EID']), safe(paper['Title']), paper['Authors'],
                ", ".join(paper['Author IDs']), ", ".join(paper['Author Affiliations']),
                safe(paper['Creators']), safe(paper['Publication Name']), safe(paper['eISSN']), safe(paper['Volume']),
                safe(paper['Page Range']), safe(paper['Cover Date']), safe(paper['DOI']), safe(paper['Cited By Count']),
                safe(paper['Aggregation Type']), safe(paper['Subtype']), safe(paper['Subtype Description']),
                safe(paper['Source ID']), safe(paper['Open Access']), safe(paper['URL']), safe(paper['Abstract']),
                safe(paper['Subject Classification']), safe(paper['Affiliation Names']),
                safe(paper['Affiliation Cities']), safe(paper['Affiliation Countries'])
            ))
            logging.info(f"✅ Inserted SCOPUS_ID: {scopus_id} | Title: {paper['Title'][:80]}")
        connection.commit()
        cursor.close()

    except Exception as e:
        logging.error(f"Database error during Scopus data insertion: {e}")
        flash("An error occurred during Scopus data insertion. Please try again later.", "error")
    finally:
        # Ensure the connection is released back to the pool
        connection.close()

    session['scopus_ids'] = [paper['SCOPUS_ID'] for paper in paper_details]
    session['query'] = query
    session.modified = True

    flash("Data fetched successfully for selected", "success")
    # Redirect to result page after data insertion
    return redirect(url_for('result', page=1, sort_by='newest'))
@app.route('/result')
def result():
    # Get current page and sorting options
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'newest')  # Default sorting is by newest
    per_page = 10  # Number of results per page

    # Retrieve the query from session
    query = session.get('query', '')  # Retrieve query from session

    # Get a connection from the pool
    connection = get_db_connection()  # Use the connection pool's connection
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        flash("Failed to get a DB connection. Please try again.", "error")
        return redirect(url_for('index'))

    # Calculate the OFFSET based on page and results per page
    offset = (page - 1) * per_page

    # Modify the query based on the sorting option
    if sort_by == 'newest':
        order_by = "`Cover Date` DESC"
    elif sort_by == 'oldest':
        order_by = "`Cover Date` ASC"
    elif sort_by == 'alphabetical':
        order_by = "`Title` ASC"
    else:
        order_by = "`Cover Date` DESC"

    # Get papers for the current page with the applied sorting
    scopus_ids = session.get('scopus_ids', [])
    if not scopus_ids:
        flash("No search results found. Please perform a search first.", "warning")
        return redirect(url_for('index'))

    # Build the query
    format_strings = ','.join(['%s'] * len(scopus_ids))
    query_sql = f"SELECT * FROM papers WHERE SCOPUS_ID IN ({format_strings}) ORDER BY {order_by} LIMIT %s OFFSET %s"

    # Use a cursor from the connection
    cursor = connection.cursor(dictionary=True)
    cursor.execute(query_sql, tuple(scopus_ids) + (per_page, offset))

    results = cursor.fetchall()
    cursor.close()

    # Get the total number of records for pagination
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM papers WHERE SCOPUS_ID IN ({format_strings})", tuple(scopus_ids))
    total_records = cursor.fetchone()[0]
    cursor.close()

    # Fetch all matching papers (not paginated) to count total staff/student
    cursor = connection.cursor(dictionary=True)
    cursor.execute(f"SELECT * FROM papers WHERE SCOPUS_ID IN ({format_strings})", tuple(scopus_ids))
    all_papers = cursor.fetchall()
    cursor.close()

    # Categorize all papers to count staff and students
    all_papers = [categorize_authors_in_paper(p, lecturers) for p in all_papers]

    staff_count = 0
    student_count = 0

    # Iterate over all papers to count staff and students correctly
    for paper in all_papers:
        # If there is any staff in the authors, count the paper as staff
        if "Staff" in paper["authors_category"]:
            staff_count += 1
        # If all authors are students, count as student
        elif all(cat == "Student" for cat in paper["authors_category"]):
            student_count += 1

    # Categorize the papers for the current page as well
    results = [categorize_authors_in_paper(paper, lecturers) for paper in results]

    # Calculate total pages
    total_pages = (total_records // per_page) + (1 if total_records % per_page > 0 else 0)
    total_results = total_records
    pagination_pages = get_pagination_pages(page, total_pages)

    # Release the connection back to the pool
    connection.close()

    # Render the results page with the sorted results
    return render_template(
        'result.html',
        results=results,
        query=query,
        page=page,
        per_page=per_page,  # Add this line
        total_pages=total_pages,
        total_results=total_results,
        sort_by=sort_by,
        pagination_pages=pagination_pages,
        staff_count=staff_count,
        student_count=student_count 
    )



def insert_paper_to_db(paper, cursor, error_log=None):
    scopus_id = safe(paper['SCOPUS_ID'])
    title = safe(paper['Title']).strip().lower()
    if scopus_id == "N/A" or title == "n/a":
        logging.warning(f"⚠️ Skipping paper with missing SCOPUS_ID or Title.")
        return

    logging.info(f"📝 Attempting to insert paper with Title: {paper['Title'][:80]}")

    try:
        # Check for duplicate based on Title (case-insensitive)
        cursor.execute("SELECT `Title` FROM papers WHERE LOWER(TRIM(`Title`)) = %s", (title,))
        existing_paper = cursor.fetchone()

        if existing_paper:
            logging.warning(f"⚠️ Duplicate detected by Title, skipping: {paper['Title'][:80]}")
            return

        # Insert record - wrap all column names with backticks (`)
        cursor.execute("""INSERT INTO papers (
            `SCOPUS_ID`, `EID`, `Title`, `Authors`, `Author IDs`, `Author Affiliations`,
            `Creators`, `Publication Name`, `eISSN`, `Volume`, `Page Range`, `Cover Date`,
            `DOI`, `Cited By Count`, `Aggregation Type`, `Subtype`, `Subtype Description`,
            `Source ID`, `Open Access`, `URL`, `Abstract`, `Subject Classification`,
            `Affiliation Names`, `Affiliation Cities`, `Affiliation Countries`
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", (
            scopus_id,
            safe(paper['EID']),
            paper['Title'],
            list_to_str(paper['Authors']),
            list_to_str(paper['Author IDs']),
            list_to_str(paper['Author Affiliations']),
            safe(paper['Creators']),
            safe(paper['Publication Name']),
            safe(paper['eISSN']),
            safe(paper['Volume']),
            safe(paper['Page Range']),
            safe(paper['Cover Date']),
            safe(paper['DOI']),
            safe(paper['Cited By Count']),
            safe(paper['Aggregation Type']),
            safe(paper['Subtype']),
            safe(paper['Subtype Description']),
            safe(paper['Source ID']),
            safe(paper['Open Access']),
            safe(paper['URL']),
            safe(paper['Abstract']),
            safe(paper['Subject Classification']),
            safe(paper['Affiliation Names']),
            safe(paper['Affiliation Cities']),
            safe(paper['Affiliation Countries'])
        ))

        db.commit()
        logging.info(f"✅ Successfully inserted paper with Title: {paper['Title'][:80]}")

    except Exception as e:
        msg = f"❌ Error inserting paper with Title: {paper['Title'][:80]} | Error: {str(e)}"
        logging.error(msg)
        if error_log is not None:
            error_log.append(msg)
        db.rollback()

@app.route('/view/<string:doc_id>')
def view_detail(doc_id):
    doc = get_document_by_id(doc_id)

    if doc:
        return render_template('view.html', doc=doc)
    else:
        flash("Document not found.", "danger")
        logging.warning(f"Document with SCOPUS_ID {doc_id} not found in the database.")
        return redirect(url_for('result'))



    
@app.route('/view2/<string:doc_id>')
def view_detail2(doc_id):
    try:
        # Assuming you're using connection pooling
        connection = get_db_connection()  # Replace with your connection pool method
        if not connection:
            flash("Database connection failed.", "error")
            return redirect(url_for('documents'))

        cursor = connection.cursor(dictionary=True)

        # Execute the query to fetch document by SCOPUS_ID
        cursor.execute("SELECT * FROM papers WHERE SCOPUS_ID = %s", (doc_id,))
        doc = cursor.fetchone()
        cursor.close()
        connection.close()  # Close connection after use

        if doc:
            return render_template('view2.html', doc=doc)
        else:
            flash("Document not found.", "danger")
            return redirect(url_for('documents'))

    except mysql.connector.Error as err:
        # Log any database connection errors or query failures
        logging.error(f"Database error: {err}")
        flash("An error occurred while fetching the document. Please try again later.", "error")
        return redirect(url_for('documents'))

    except Exception as e:
        # Log any unexpected errors
        logging.error(f"Unexpected error: {e}")
        flash("An unexpected error occurred. Please try again later.", "error")
        return redirect(url_for('documents'))


def search_author(first_name, last_name):
    # Fetch the current API key from the database or configuration
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database.")
        return None

    # Build the query
    query = f'AUTHLAST({last_name})'
    if first_name:
        query += f' AND AUTHFIRST({first_name})'

    params = {"query": query, "count": 1}
    url = "https://api.elsevier.com/content/search/author"
    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}

    try:
        # Make the API call to search for the author
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            # If successful, extract the first author entry
            results = response.json().get("search-results", {}).get("entry", [])
            if results:
                author = results[0]
                full_name = f"{author.get('preferred-name', {}).get('given-name', '')} {author.get('preferred-name', {}).get('surname', '')}".strip() or "N/A"
                author_id = author.get("dc:identifier", "").split(":")[-1]  # Extract the author ID from the identifier string
                affiliation = author.get("affiliation-current", {}).get("affiliation-name", "N/A")  # Default to "N/A" if no affiliation found

                logging.info(f"Found author: {full_name} ({author_id})")
                return {
                    "author_id": author_id,
                    "name": full_name,
                    "affiliation": affiliation
                }
            else:
                logging.warning(f"No results found for author {first_name} {last_name}")
        else:
            logging.error(f"API request failed for author {first_name} {last_name}, status code: {response.status_code}, response: {response.text}")

    except requests.exceptions.RequestException as e:
        # Handle network issues or request exceptions
        logging.error(f"Error while requesting author data for {first_name} {last_name}: {e}")
    
    return None
def get_author_metrics(author_id):
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database.")
        return {}

    url = f"https://api.elsevier.com/content/author/author_id/{author_id}?view=ENHANCED"
    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json().get("author-retrieval-response", [{}])[0]
        coredata = data.get("coredata", {})
        subjects = data.get("subject-areas", {}).get("subject-area", [])
        subject_areas = [s.get("$", "N/A") for s in subjects] if isinstance(subjects, list) else []

        return {
            "h_index": data.get("h-index", "N/A"),
            "citation_count": coredata.get("citation-count", "N/A"),
            "document_count": coredata.get("document-count", "N/A"),
            "subject_areas": ", ".join(subject_areas)
        }
    else:
        logging.error(f"Failed to get metrics for author_id {author_id}, status code: {response.status_code}")

    return {}


def get_author_documents(author_id):
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database.")
        return []

    url = "https://api.elsevier.com/content/search/scopus"
    query = f"AU-ID({author_id})"
    params = {"query": query, "count": 200}
    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}

    response = requests.get(url, headers=headers, params=params)

    documents = []
    if response.status_code == 200:
        for entry in response.json().get("search-results", {}).get("entry", []):
            documents.append({
                "scopus_id": entry.get("dc:identifier", "N/A").split(":")[-1],
                "title": entry.get("dc:title", "N/A"),
                "publication": entry.get("prism:publicationName", "N/A"),
                "date": entry.get("prism:coverDate", "N/A"),
                "doi": entry.get("prism:doi", "N/A"),
                "cited_by": entry.get("citedby-count", "0"),
                "url": entry.get("prism:url", "N/A")
            })
            time.sleep(1)
    else:
        logging.error(f"Failed to get documents for author_id {author_id}, status code: {response.status_code}")

    return documents


def save_author_to_db(author_info, documents):
    # Get a connection from the pool
    connection = db.get_connection()  # This assumes you have a connection pool
    cursor = connection.cursor()

    try:
        # Start a transaction
        connection.start_transaction()

        # Insert into authors table (if not exists)
        cursor.execute("SELECT * FROM author WHERE author_id = %s", (author_info['author_id'],))
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO author (author_id, name, affiliation, h_index, citation_count, document_count, subject_areas)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                author_info["author_id"], author_info["name"], author_info["affiliation"],
                author_info["h_index"], author_info["citation_count"],
                author_info["document_count"], author_info["subject_areas"]
            ))

        # Insert documents (skip duplicates)
        for doc in documents:
            cursor.execute("SELECT * FROM document WHERE scopus_id = %s", (doc["scopus_id"],))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO document (author_id, scopus_id, title, publication, date, doi, cited_by, url)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    author_info["author_id"], doc["scopus_id"], doc["title"], doc["publication"],
                    doc["date"], doc["doi"], doc["cited_by"], doc["url"]
                ))

        # Commit the transaction
        connection.commit()
        logging.info(f"Author {author_info['name']} and {len(documents)} documents saved successfully.")

    except mysql.connector.Error as err:
        # Rollback in case of error
        connection.rollback()
        logging.error(f"Error saving author {author_info['name']} to database: {err}")

    finally:
        cursor.close()
        connection.close()

def get_pagination_pages(current_page, total_pages, max_pages=7):
    pages = []

    if total_pages <= max_pages:
        # Show all pages if total is less than max allowed
        return list(range(1, total_pages + 1))

    # Number of pages to show in the sliding window (excluding first and last pages)
    num_middle_pages = max_pages - 2  # reserve slots for first and last page

    # Calculate start and end for sliding window around current_page
    half_window = num_middle_pages // 2
    start_page = current_page - half_window
    end_page = current_page + half_window

    # Adjust if start_page is too close to beginning
    if start_page < 2:
        start_page = 2
        end_page = start_page + num_middle_pages - 1

    # Adjust if end_page is too close to the end
    if end_page > total_pages - 1:
        end_page = total_pages - 1
        start_page = end_page - num_middle_pages + 1

    # Add first page always
    pages.append(1)

    # Add ellipsis if there is a gap between first page and start_page
    if start_page > 2:
        pages.append('...')

    # Add the sliding window pages
    pages.extend(range(start_page, end_page + 1))

    # Add ellipsis if there is a gap between end_page and last page
    if end_page < total_pages - 1:
        pages.append('...')

    # Add last page always
    pages.append(total_pages)

    return pages

# Function for fuzzy search and logging
def fuzzy_search_author(first_name, last_name):
    cursor = db.cursor(dictionary=True)
    
    # Fetch authors from the database, limit to 500 authors for better performance (adjust if necessary)
    cursor.execute("SELECT author_id, name FROM author LIMIT 500")  
    authors = cursor.fetchall()

    # Combine first and last name for the search query
    full_name = f"{first_name} {last_name}".strip().lower()
    
    # Use fuzzywuzzy for matching
    matches = process.extract(full_name, [author['name'].lower() for author in authors], limit=5)
    
    # Log the fuzzy search process
    logging.info(f"🔍 Performing fuzzy search for: {full_name}")
    
    similar_authors = []
    for match in matches:
        if match[1] > 80:  # Adjust threshold as needed
            # Find the exact match from the list of authors
            author = next(a for a in authors if a['name'].lower() == match[0])
            similar_authors.append(author)
            logging.info(f"✅ Found author: {author['name']} with match score: {match[1]}")

    cursor.close()
    
    # If no matches are found
    if not similar_authors:
        logging.warning(f"⚠️ No authors found matching {full_name} with a high enough score.")
    
    return similar_authors
@app.route('/author_search', methods=['POST'])
def author_search():
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()

    if not first_name:
        flash("First name is required.", "danger")
        logging.warning("❌ First name was not provided.")
        return redirect(url_for('index'))

    # Store the first name and last name in the session
    session['first_name'] = first_name
    session['last_name'] = last_name
    session.modified = True

    # Get a connection from the pool
    connection = db.get_connection()

    try:
        cursor = connection.cursor(dictionary=True)

        # Check if the author exists in the database using first name only
        cursor.execute("SELECT * FROM author WHERE name LIKE %s", (f"%{first_name}%",))  
        author = cursor.fetchone()

        if author:
            # If the author exists, fetch associated documents
            logging.info(f"✅ Found author: {author['name']} with author_id: {author['author_id']}")

            # Fetch documents related to the author
            cursor.execute("SELECT * FROM document WHERE author_id = %s", (author["author_id"],))
            documents = cursor.fetchall()

            flash(f"Author {author['name']} found with {len(documents)} documents.", "success")
            logging.info(f"✅ Displayed {len(documents)} documents for author {author['name']}.")

            return render_template('author_detail.html', author=author, documents=documents)
        else:
            # If the author is not found in the database, fetch from Scopus
            flash(f"Author {first_name} {last_name} not found in the database. Fetching data from Scopus...", "warning")
            author_info = search_author(first_name, last_name)  # Pass both first_name and last_name

            if author_info:
                metrics = get_author_metrics(author_info["author_id"])
                author_info.update(metrics)

                documents = get_author_documents(author_info["author_id"])
                save_author_to_db(author_info, documents)

                flash(f"Author {author_info['name']} and {len(documents)} documents saved.", "success")
                logging.info(f"✅ Author {author_info['name']} and {len(documents)} documents saved.")
            else:
                flash(f"Author {first_name} {last_name} not found in Scopus.", "warning")

            return redirect(url_for('authors'))

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        flash("An error occurred while accessing the database.", "error")
        return redirect(url_for('index'))

    finally:
        # Always close the cursor and connection
        if cursor:
            cursor.close()
        if connection:
            connection.close()  # Return the connection to the pool

# === 📄 Author List Page ===
@app.route('/authors')
def authors():
    # Get a connection from the pool
    connection = get_db_connection()  # Assuming get_db_connection() retrieves a connection from the pool
    if connection is None:
        flash("Error: Could not get a DB connection.", "error")
        return redirect(url_for('index'))

    try:
        cursor = connection.cursor(dictionary=True)

        first_name = session.get('first_name', None)
        last_name = session.get('last_name', None)

        # Log session values for debugging
        logging.info(f"First Name from Session: {first_name}")
        logging.info(f"Last Name from Session: {last_name}")

        if first_name and last_name:
            cursor.execute("SELECT * FROM author WHERE name LIKE %s", (f"%{first_name}%",))
        else:
            cursor.execute("SELECT * FROM author ORDER BY name")

        authors = cursor.fetchall()
        logging.info(f"Fetched authors: {authors}")  # Log the authors list

        # Debugging: Check if the authors list is empty or has issues
        if not authors:
            logging.warning("No authors found in the database.")

        return render_template('result2.html', authors=authors)

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        flash("An error occurred while fetching authors.", "error")
        return redirect(url_for('index'))

    finally:
        # Ensure the connection is released back to the pool
        connection.close()  # Release the connection back to the pool

# === 🔍 View Documents for a Specific Author ===
@app.route('/author/<author_id>')
def author_detail(author_id):
    # Get a connection from the pool
    connection = get_db_connection()  # Assuming get_db_connection() retrieves a connection from the pool
    if connection is None:
        flash("Error: Could not get a DB connection.", "error")
        return redirect(url_for('index'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get author info
        cursor.execute("SELECT * FROM author WHERE author_id = %s", (author_id,))
        author = cursor.fetchone()

        if not author:
            flash("Author not found.", "danger")
            return redirect(url_for('authors'))

        # Get their documents
        cursor.execute("SELECT * FROM document WHERE author_id = %s", (author_id,))
        documents = cursor.fetchall()

        # Pass the author and document data to the template
        return render_template('author_detail.html', author=author, documents=documents)

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        flash("An error occurred while fetching the author details.", "error")
        return redirect(url_for('index'))

    finally:
        # Ensure the connection is released back to the pool
        connection.close()  # Release the connection back to the pool

@app.route('/export_all_results', methods=['POST'])
def export_all_results():
    # Get all scopus_ids from the session (these are the papers currently being displayed)
    scopus_ids = session.get('scopus_ids', [])
    if not scopus_ids:
        flash("No results to export.", "warning")
        return redirect(url_for('index'))  # If no results are found, redirect back to the index page

    # Get a connection from the pool
    connection = get_db_connection()
    if connection is None:
        flash("Failed to get a DB connection. Please try again.", "error")
        return redirect(url_for('index'))

    # Create cursor from the connection
    cursor = connection.cursor(dictionary=True)
    format_strings = ','.join(['%s'] * len(scopus_ids))
    cursor.execute(f"SELECT * FROM papers WHERE SCOPUS_ID IN ({format_strings})", tuple(scopus_ids))
    selected_docs = cursor.fetchall()
    cursor.close()

    # Create CSV file from the results
    from io import StringIO
    output = StringIO()
    fieldnames = [
        'SCOPUS_ID', 'EID', 'Title', 'Authors', 'Author IDs', 'Author Affiliations',
        'Creators', 'Publication Name', 'eISSN', 'Volume', 'Page Range', 'Cover Date',
        'DOI', 'Cited By Count', 'Aggregation Type', 'Subtype', 'Subtype Description',
        'Source ID', 'Open Access', 'URL', 'Abstract', 'Subject Classification',
        'Affiliation Names', 'Affiliation Cities', 'Affiliation Countries'
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
    writer.writeheader()

    for doc in selected_docs:
        # Convert any None values to 'N/A'
        for key in fieldnames:
            if doc.get(key) is None:
                doc[key] = 'N/A'
            elif isinstance(doc[key], list):
                doc[key] = '; '.join(str(item) for item in doc[key])  # Convert list to string

        writer.writerow({k: doc.get(k, 'N/A') for k in fieldnames})

    # Flash success message after the export
    flash("Data successfully exported!", "success")

    # Create the CSV file as a response
    response = Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=exported_all_documents.csv"}
    )
    return response

@app.route('/lecturer_info', methods=['GET', 'POST'])
def lecturer_info():
    # Check if the admin is logged in
    if not session.get('admin_logged_in'):
        flash("You need to log in first.", "warning")
        return redirect(url_for('index'))  # Redirect to login page if not logged in
    
    search_query = request.args.get('search_query', '')
    page = request.args.get('page', 1, type=int)  # Handle pagination
    per_page = 10  # Number of results per page

    try:
        connection = get_db_connection()  # Assuming you're using a connection pool
        if not connection:
            flash("Database connection failed.", "error")
            return redirect(url_for('index'))
        
        cursor = connection.cursor(dictionary=True)

        # Calculate the OFFSET based on page and results per page
        offset = (page - 1) * per_page
        
        # Build the query based on search input
        query = "SELECT * FROM lecturer"
        params = []
        
        if search_query:
            query += " WHERE LOWER(`Nama Staf`) LIKE %s OR LOWER(`indexed_name`) LIKE %s"
            params.extend([f"%{search_query.lower()}%", f"%{search_query.lower()}%"])

        query += " LIMIT %s OFFSET %s"
        params.extend([per_page, offset])  # Add pagination to the query

        cursor.execute(query, tuple(params))
        lecturers = cursor.fetchall()

        # Get the total number of lecturers for pagination
        cursor.execute("SELECT COUNT(*) FROM lecturer")
        total_count = cursor.fetchone()[0]

        cursor.close()

        # Calculate total pages for pagination
        total_pages = (total_count // per_page) + (1 if total_count % per_page > 0 else 0)

        return render_template('lecturer.html', lecturers=lecturers, search_query=search_query, page=page,
                               total_pages=total_pages, total_count=total_count)

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        flash("An error occurred while fetching data. Please try again later.", "error")
        return redirect(url_for('index'))

    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        flash("An unexpected error occurred. Please try again later.", "error")
        return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)  # Remove the admin login status from the session
    flash("You have logged out.", "info")
    return redirect(url_for('index'))  # Redirect back to the index page

@app.route('/add_lecturer', methods=['POST'])
def add_lecturer():
    # Get a connection from the connection pool
    connection = get_db_connection()  # Assuming get_db_connection() retrieves a connection from the pool
    if connection is None:
        flash("Error: Could not get a DB connection.", "error")
        return redirect(url_for('lecturer_info'))

    try:
        # Retrieve the form data
        staff_id = request.form['staff_id']
        name = request.form['name']
        department = request.form['department']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        indexed_name = request.form['indexed_name']

        cursor = connection.cursor()

        # Insert lecturer data into the database
        cursor.execute("""
            INSERT INTO lecturer (`No Staf`, `Nama Staf`, `Pusat Pengajian`, `First Name`, `Last Name`, `indexed_name`)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (staff_id, name, department, first_name, last_name, indexed_name))

        # Commit the transaction to the database
        connection.commit()

        # Flash success message
        flash("Lecturer added successfully!", "success")

    except Exception as e:
        # Rollback in case of error
        connection.rollback()
        flash(f"Error: {str(e)}. Lecturer was not added.", "error")

    finally:
        # Ensure that the cursor and connection are properly closed
        cursor.close()
        connection.close()  # Release the connection back to the pool

    return redirect(url_for('lecturer_info'))

@app.route('/update_lecturer', methods=['POST'])
def update_lecturer():
    # Get a connection from the connection pool
    connection = get_db_connection()  # Assuming get_db_connection() retrieves a connection from the pool
    if connection is None:
        flash("Error: Could not get a DB connection.", "error")
        return redirect(url_for('lecturer_info'))

    # Retrieve the form data
    staff_id = request.form['staff_id']
    name = request.form['name']
    department = request.form['department']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    indexed_name = request.form['indexed_name']

    try:
        cursor = connection.cursor()

        # Update lecturer information in the database
        cursor.execute("""
            UPDATE lecturer 
            SET `Nama Staf` = %s, `Pusat Pengajian` = %s, `First Name` = %s, `Last Name` = %s, `indexed_name` = %s
            WHERE `No Staf` = %s
        """, (name, department, first_name, last_name, indexed_name, staff_id))

        # Commit the transaction to the database
        connection.commit()

        # Flash success message
        flash("Lecturer updated successfully!", "success")

    except Exception as e:
        # Rollback in case of error
        connection.rollback()
        flash(f"Error: {str(e)}. Lecturer was not updated.", "error")

    finally:
        # Ensure that the cursor and connection are properly closed
        cursor.close()
        connection.close()  # Release the connection back to the pool

    return redirect(url_for('lecturer_info'))

@app.route('/delete_lecturer/<int:lecturer_id>', methods=['GET'])
def delete_lecturer(lecturer_id):
    # Get a connection from the connection pool
    connection = get_db_connection()  # Using the connection pool
    if connection is None:
        flash("Error: Could not get a DB connection.", "error")
        return redirect(url_for('lecturer_info'))

    try:
        cursor = connection.cursor()

        # Deleting the lecturer from the 'lecturer' table
        cursor.execute("DELETE FROM lecturer WHERE `No Staf` = %s", (lecturer_id,))
        
        # Commit the transaction
        connection.commit()

        # Flash success message
        flash("Lecturer deleted successfully!", "success")

    except Exception as e:
        # Rollback the transaction in case of an error
        connection.rollback()
        flash(f"Error: {str(e)}. Lecturer was not deleted.", "error")

    finally:
        # Ensure that the cursor and connection are properly closed
        cursor.close()
        connection.close()  # Release the connection back to the pool

    return redirect(url_for('lecturer_info'))

@app.route('/admin_sync_dashboard')
def admin_sync_dashboard():
    # Check if admin is logged in
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('index'))

    # Get the current API key
    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database for sync dashboard.")
        flash("No API key configured. Please add one in the admin panel.", "error")
        return redirect(url_for('admin_api_keys'))

    try:
        # Get a connection from the pool
        connection = get_db_connection()
        if connection is None:
            logging.error("Failed to get a DB connection from the pool.")
            flash("Failed to get a DB connection from the pool.", "error")
            return redirect(url_for('admin_sync_dashboard'))

        cursor = connection.cursor(dictionary=True)

        # Fetch all distinct years from papers
        cursor.execute("SELECT DISTINCT YEAR(STR_TO_DATE(`Cover Date`, '%Y-%m-%d')) AS year FROM papers ORDER BY year DESC")
        paper_years = [row['year'] for row in cursor.fetchall() if row['year'] is not None]

        # Set up the affiliation query filter
        aff_ids = ["60002763", "60212344", "60228314", "60228313", "60212346"]
        aff_query = " OR ".join([f"AF-ID({aff_id})" for aff_id in aff_ids])
        headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}

        sync_data = []

        # 1. Process existing years
        for year in paper_years:
            cursor.execute("SELECT COUNT(*) AS count FROM papers WHERE `Cover Date` LIKE %s", (f"{year}%",))
            db_count = cursor.fetchone()['count']

            # Build query for Scopus API
            full_query = f"PUBYEAR IS {year} AND ({aff_query})"
            params = {"query": full_query, "count": 0}
            response = requests.get(SCOPUS_SEARCH_URL, headers=headers, params=params)
            update_api_key_last_used(api_key)

            api_count = 0
            if response.status_code == 200:
                api_count = int(response.json().get("search-results", {}).get("opensearch:totalResults", 0))
            else:
                logging.warning(f"Scopus API error for year {year}, status: {response.status_code}")

            # Fetch the sync log for this year to get the last synced date
            cursor.execute("SELECT * FROM scopus_sync_log WHERE year = %s", (year,))
            log = cursor.fetchone()

            # Calculate sync percentage and ensure it's capped at 100%
            if api_count > 0:
                sync_percentage = round((db_count / api_count) * 100, 2)
                sync_percentage = min(sync_percentage, 100.0)  # Cap at 100%
            else:
                sync_percentage = 100.0  # Assume fully synced if no API records

            # Insert or update the sync log for this year
            cursor.execute(""" 
                INSERT INTO scopus_sync_log (year, db_count, api_count, sync_percentage, last_synced_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE db_count=%s, api_count=%s, sync_percentage=%s, last_synced_at=NOW()
            """, (year, db_count, api_count, sync_percentage, db_count, api_count, sync_percentage))

            # Append the sync data for the year
            sync_data.append({
                "year": year,
                "db_count": db_count,
                "api_count": api_count,
                "last_synced_at": log['last_synced_at'] if log else None,
                "sync_percentage": sync_percentage
            })

        # 2. Process future years (from the current year up to 5 years ahead)
        current_year = datetime.now().year
        max_year = max(paper_years) if paper_years else current_year
        future_years = range(max_year + 1, current_year + 6)

        for year in future_years:
            full_query = f"PUBYEAR IS {year} AND ({aff_query})"
            params = {"query": full_query, "count": 0}
            response = requests.get(SCOPUS_SEARCH_URL, headers=headers, params=params)
            update_api_key_last_used(api_key)

            if response.status_code == 200:
                api_count = int(response.json().get("search-results", {}).get("opensearch:totalResults", 0))
                if api_count > 0:
                    # For future years, db_count is 0, and sync_percentage is 0%
                    sync_data.append({
                        "year": year,
                        "db_count": 0,
                        "api_count": api_count,
                        "last_synced_at": None,
                        "sync_percentage": 0.0
                    })

                    # Insert sync log for future year with 0 db_count and sync_percentage
                    cursor.execute(""" 
                        INSERT INTO scopus_sync_log (year, db_count, api_count, sync_percentage, last_synced_at)
                        VALUES (%s, %s, %s, %s, NOW())
                        ON DUPLICATE KEY UPDATE db_count=%s, api_count=%s, sync_percentage=%s, last_synced_at=NOW()
                    """, (year, 0, api_count, 0.0, 0, api_count, 0.0))
            else:
                logging.warning(f"Scopus API error for future year {year}, status: {response.status_code}")

        # Commit changes to the database
        connection.commit()

        # Close the cursor and release the connection back to the pool
        cursor.close()
        connection.close()

        # Sort sync data by year in descending order
        sync_data.sort(key=lambda x: x['year'], reverse=True)

        # Render the template with the sync data
        return render_template('admin_sync_dashboard.html', sync_data=sync_data)

    except mysql.connector.Error as err:
        logging.error(f"Database connection error: {err}")
        flash("Database connection error. Please try again later.", "error")
        return redirect(url_for('index'))
    
@app.route('/sync_year/<int:year>', methods=['POST'])
def sync_scopus_year(year):
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('index'))

    api_key = get_current_api_key()
    if not api_key:
        logging.error("No API key found in database.")
        flash("No API key configured. Please add one in the admin panel.", "error")
        return redirect(url_for('admin_api_keys'))

    # Get connection from the pool
    connection = get_db_connection()
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        flash("Failed to get a DB connection from the pool.", "error")
        return redirect(url_for('admin_sync_dashboard'))
    
    cursor = connection.cursor()

    aff_ids = ["60002763", "60212344", "60228314", "60228313", "60212346"]
    aff_query = " OR ".join([f"AF-ID({aff_id})" for aff_id in aff_ids])
    full_query = f"PUBYEAR IS {year} AND ({aff_query})"
    headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}

    # Existing paper IDs for this year
    cursor.execute("SELECT `SCOPUS_ID` FROM papers WHERE `Cover Date` LIKE %s", (f"{year}%",))
    existing_ids = {row[0] for row in cursor.fetchall()}

    params = {"query": full_query, "count": 0}
    response = requests.get(SCOPUS_SEARCH_URL, headers=headers, params=params)
    update_api_key_last_used(api_key)

    if response.status_code != 200:
        flash(f"Failed to fetch API count for {year}.", "error")
        cursor.close()
        connection.close()  # Close connection when done
        return redirect(url_for('admin_sync_dashboard'))

    api_count = int(response.json().get("search-results", {}).get("opensearch:totalResults", 0))
    if api_count == 0:
        flash(f"No data found for year {year}.", "info")
        cursor.close()
        connection.close()  # Close connection when done
        return redirect(url_for('admin_sync_dashboard'))

    # Fetch data in batches
    offset = 0
    batch_size = 50
    all_papers = []

    while offset < api_count:
        params = {"query": full_query, "count": batch_size, "start": offset}
        response = requests.get(SCOPUS_SEARCH_URL, headers=headers, params=params)
        update_api_key_last_used(api_key)

        if response.status_code != 200:
            flash(f"API error {response.status_code} at offset {offset}", "error")
            break

        entries = response.json().get("search-results", {}).get("entry", [])
        if not entries:
            break

        papers = extract_paper_details({"search-results": {"entry": entries}})
        new_papers = [p for p in papers if p['SCOPUS_ID'] not in existing_ids]
        all_papers.extend(new_papers)

        offset += batch_size
        time.sleep(1)

    if not all_papers:
        flash(f"No new papers to insert for year {year}.", "info")
        cursor.close()
        connection.close()  # Close connection when done
        return redirect(url_for('admin_sync_dashboard'))

    save_to_csv(all_papers, year)
    insert_csv_to_db(f"scopus_data_{year}.csv")

    cursor.execute("""
        INSERT INTO scopus_sync_log (year, db_count, api_count, last_synced_at)
        VALUES (%s, %s, %s, NOW())
        ON DUPLICATE KEY UPDATE db_count=%s, api_count=%s, last_synced_at=NOW()
    """, (year, len(existing_ids) + len(all_papers), api_count, len(existing_ids) + len(all_papers), api_count))

    connection.commit()  # Commit the transaction
    cursor.close()
    connection.close()  # Release the connection back to the pool

    flash(f"{len(all_papers)} new papers inserted for year {year}.", "success")
    return redirect(url_for('admin_sync_dashboard'))

# --- app.py ---
@app.route('/documents')
def documents():
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('index'))

    # Get the search query and year from the form
    search_query = request.args.get('search_query', '').strip()  # Remove leading/trailing spaces
    selected_year = request.args.get('year', '').strip()

    print(f"Search Query: {search_query}, Selected Year: {selected_year}")  # Debug print

    connection = get_db_connection()  # Assuming you're using connection pooling
    if not connection:
        flash("Database connection failed.", "error")
        return redirect(url_for('index'))
    
    cursor = connection.cursor(dictionary=True)

    # Fetch distinct years directly from the database for filtering
    cursor.execute("SELECT DISTINCT YEAR(`Cover Date`) AS year FROM papers WHERE `Cover Date` IS NOT NULL ORDER BY year DESC")
    years = [row['year'] for row in cursor.fetchall()]

    # Initialize query and params
    query = "SELECT * FROM papers"
    params = []

    # Apply search filter (if any)
    if search_query:
        query += " WHERE (LOWER(Title) LIKE %s OR LOWER(SCOPUS_ID) LIKE %s)"
        params.extend([f"%{search_query.lower()}%", f"%{search_query.lower()}%"])

    # Apply year filter (if selected)
    if selected_year:
        if 'WHERE' in query:
            query += " AND YEAR(`Cover Date`) = %s"
        else:
            query += " WHERE YEAR(`Cover Date`) = %s"
        params.append(selected_year)

    query += " ORDER BY `Cover Date` DESC"  # Ensure results are ordered by cover date

    # Execute the query with the parameters
    cursor.execute(query, tuple(params))
    documents = cursor.fetchall()

    # Process each document to check for missing data
    for doc in documents:
        missing_info = []

        # Check for missing fields
        if not doc.get('Authors'):
            missing_info.append("Authors")
        if not doc.get('Author IDs'):
            missing_info.append("Author IDs")
        if not doc.get('Abstract'):
            missing_info.append("Abstract")
        if not doc.get('Subject Classification'):
            missing_info.append("Subject Classification")
        if not doc.get('Affiliation Names'):
            missing_info.append("Affiliation Names")

        # If there are missing fields, add them to the `missing_info` field
        if missing_info:
            doc['missing_info'] = ", ".join(missing_info) + " missing"
        else:
            doc['missing_info'] = "All data available"  # If nothing is missing

    # Count the total number of results
    total_results = len(documents)

    cursor.close()
    connection.close()  # Close the connection after use

    # Pass data to the template
    return render_template('documents.html', 
                           documents=documents, 
                           search_query=search_query, 
                           years=years, 
                           selected_year=selected_year, 
                           total_results=total_results)

# Function to save data to a CSV file with dynamic naming based on year
def save_to_csv(papers, year, file_path_template="scopus_data_{year}.csv"):
    file_path = file_path_template.format(year=year)
    fieldnames = [
        'SCOPUS_ID', 'EID', 'Title', 'Authors', 'Author IDs', 'Author Affiliations',
        'Creators', 'Publication Name', 'eISSN', 'Volume', 'Page Range', 'Cover Date',
        'DOI', 'Cited By Count', 'Aggregation Type', 'Subtype', 'Subtype Description',
        'Source ID', 'Open Access', 'URL', 'Abstract', 'Subject Classification',
        'Affiliation Names', 'Affiliation Cities', 'Affiliation Countries'
    ]

    # Overwrite CSV file instead of appending
    with open(file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()  # Always write headers on overwrite

        for paper in papers:
            writer.writerow({
                'SCOPUS_ID': safe(paper['SCOPUS_ID']),
                'EID': safe(paper['EID']),
                'Title': paper['Title'],
                'Authors': list_to_str(paper['Authors']),
                'Author IDs': list_to_str(paper['Author IDs']),
                'Author Affiliations': list_to_str(paper['Author Affiliations']),
                'Creators': safe(paper['Creators']),
                'Publication Name': safe(paper['Publication Name']),
                'eISSN': safe(paper['eISSN']),
                'Volume': safe(paper['Volume']),
                'Page Range': safe(paper['Page Range']),
                'Cover Date': safe(paper['Cover Date']),
                'DOI': safe(paper['DOI']),
                'Cited By Count': safe(paper['Cited By Count']),
                'Aggregation Type': safe(paper['Aggregation Type']),
                'Subtype': safe(paper['Subtype']),
                'Subtype Description': safe(paper['Subtype Description']),
                'Source ID': safe(paper['Source ID']),
                'Open Access': safe(paper['Open Access']),
                'URL': safe(paper['URL']),
                'Abstract': safe(paper['Abstract']),
                'Subject Classification': safe(paper['Subject Classification']),
                'Affiliation Names': safe(paper['Affiliation Names']),
                'Affiliation Cities': safe(paper['Affiliation Cities']),
                'Affiliation Countries': safe(paper['Affiliation Countries'])
            })

    print(f"Data saved to CSV file: {file_path}")

def insert_csv_to_db(file_path="scopus_data.csv"):
    # Get a connection from the pool
    connection = get_db_connection()  # Use the connection pool's connection
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        return "Error: Could not get a DB connection."

    cursor = connection.cursor()

    # Open and read the specific CSV file for the year
    with open(file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)

        # Prepare the list of tuples for bulk insert
        rows_to_insert = []

        # Prepare the insert query
        query = """
            INSERT INTO papers (
                `SCOPUS_ID`, `EID`, `Title`, `Authors`, `Author IDs`, `Author Affiliations`,
                `Creators`, `Publication Name`, `eISSN`, `Volume`, `Page Range`, `Cover Date`,
                `DOI`, `Cited By Count`, `Aggregation Type`, `Subtype`, `Subtype Description`,
                `Source ID`, `Open Access`, `URL`, `Abstract`, `Subject Classification`,
                `Affiliation Names`, `Affiliation Cities`, `Affiliation Countries`
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                `EID` = VALUES(`EID`),
                `Title` = VALUES(`Title`),
                `Authors` = VALUES(`Authors`),
                `Author IDs` = VALUES(`Author IDs`),
                `Author Affiliations` = VALUES(`Author Affiliations`),
                `Creators` = VALUES(`Creators`),
                `Publication Name` = VALUES(`Publication Name`),
                `eISSN` = VALUES(`eISSN`),
                `Volume` = VALUES(`Volume`),
                `Page Range` = VALUES(`Page Range`),
                `Cover Date` = VALUES(`Cover Date`),
                `DOI` = VALUES(`DOI`),
                `Cited By Count` = VALUES(`Cited By Count`),
                `Aggregation Type` = VALUES(`Aggregation Type`),
                `Subtype` = VALUES(`Subtype`),
                `Subtype Description` = VALUES(`Subtype Description`),
                `Source ID` = VALUES(`Source ID`),
                `Open Access` = VALUES(`Open Access`),
                `URL` = VALUES(`URL`),
                `Abstract` = VALUES(`Abstract`),
                `Subject Classification` = VALUES(`Subject Classification`),
                `Affiliation Names` = VALUES(`Affiliation Names`),
                `Affiliation Cities` = VALUES(`Affiliation Cities`),
                `Affiliation Countries` = VALUES(`Affiliation Countries`)
        """

        # Read the rows from the CSV file and prepare them for bulk insert
        for row in reader:
            rows_to_insert.append((
                row['SCOPUS_ID'],
                row['EID'],
                row['Title'],
                row['Authors'],
                row['Author IDs'],
                row['Author Affiliations'],
                row['Creators'],
                row['Publication Name'],
                row['eISSN'],
                row['Volume'],
                row['Page Range'],
                row['Cover Date'],
                row['DOI'],
                row['Cited By Count'],
                row['Aggregation Type'],
                row['Subtype'],
                row['Subtype Description'],
                row['Source ID'],
                row['Open Access'],
                row['URL'],
                row['Abstract'],
                row['Subject Classification'],
                row['Affiliation Names'],
                row['Affiliation Cities'],
                row['Affiliation Countries']
            ))

        # Perform bulk insert using executemany
        try:
            cursor.executemany(query, rows_to_insert)
            connection.commit()
        except Exception as e:
            logging.error(f"Error inserting data from CSV: {e}")
            connection.rollback()

    cursor.close()
    connection.close()  # Release the connection back to the pool
    logging.info(f"Data successfully inserted from CSV into the database.")

@app.route('/overview')
def overview():
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('index'))

    # Fetch the year from the query parameter if available
    year = request.args.get('year', None)

    # Get a connection from the pool
    connection = get_db_connection()  # Use the connection pool's connection
    if connection is None:
        logging.error("Failed to get a DB connection from the pool.")
        flash("Failed to get a DB connection. Please try again.", "error")
        return redirect(url_for('index'))

    # Query for Subtype Description distribution
    cursor = connection.cursor(dictionary=True)
    if year:
        cursor.execute("""
            SELECT `Subtype Description`, COUNT(*) AS count
            FROM papers
            WHERE YEAR(STR_TO_DATE(`Cover Date`, '%Y-%m-%d')) = %s
            GROUP BY `Subtype Description`
        """, (year,))
    else:
        cursor.execute("""
            SELECT `Subtype Description`, COUNT(*) AS count
            FROM papers
            GROUP BY `Subtype Description`
        """)
    subtype_counts = cursor.fetchall()
    cursor.close()

    # Prepare labels and counts for the subtype distribution pie chart
    labels = [row['Subtype Description'] or 'Unknown' for row in subtype_counts]
    counts = [row['count'] for row in subtype_counts]

    # Fetch distinct years for dropdown
    cursor = connection.cursor()
    cursor.execute("SELECT DISTINCT YEAR(STR_TO_DATE(`Cover Date`, '%Y-%m-%d')) AS year FROM papers ORDER BY year DESC")
    years = [row[0] for row in cursor.fetchall() if row[0] is not None]
    cursor.close()

    # Query the scopus_sync_log table for all db_count and api_count per year and last synced date
    cursor = connection.cursor(dictionary=True)
    cursor.execute("""
        SELECT year, db_count, api_count, last_synced_at
        FROM scopus_sync_log
        ORDER BY year DESC
    """)
    sync_data = cursor.fetchall()  # Get all data
    cursor.close()

    # Prepare the sync data for the line graph
    sync_years = [row['year'] for row in sync_data]
    db_counts = [row['db_count'] for row in sync_data]
    api_counts = [row['api_count'] for row in sync_data]
    last_synced_publications = sync_data[0]['last_synced_at'] if sync_data else 'No sync data available'

    # Fetch staff and student counts per year for visualization
    cursor = connection.cursor(dictionary=True)
    cursor.execute("""
        SELECT year, staff_count, student_count, last_updated
        FROM publication_counts
        ORDER BY year DESC
    """)
    pub_counts = cursor.fetchall()  # Get all data
    cursor.close()

    # Prepare data for stacked bar chart
    staff_count = [row['staff_count'] for row in pub_counts]
    student_count = [row['student_count'] for row in pub_counts]
    last_updated_publications = pub_counts[0]['last_updated'] if pub_counts else 'No data available'

    # Release the connection back to the pool
    connection.close()

    return render_template('overview.html',
                           subtype_labels=labels,
                           subtype_counts=counts,
                           subtype_year=year,
                           years=years,
                           sync_years=sync_years,
                           db_counts=db_counts,
                           api_counts=api_counts,
                           staff_counts=staff_count,
                           student_counts=student_count,
                           last_synced_publications=last_synced_publications,
                           last_updated_publications=last_updated_publications)

@app.route('/delete_document/<string:scopus_id>', methods=['POST'])
def delete_document(scopus_id):
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('index'))
    
    try:
        # Get a connection from the pool
        connection = get_db_connection()
        if connection is None:
            flash("Failed to get a DB connection. Please try again.", "error")
            return redirect(url_for('documents'))

        cursor = connection.cursor()
        cursor.execute("DELETE FROM papers WHERE SCOPUS_ID = %s", (scopus_id,))
        connection.commit()
        cursor.close()

        # Return the connection to the pool
        connection.close()

        flash("Document deleted successfully!", "success")
    except Exception as e:
        if connection:
            connection.rollback()  # Rollback transaction on error
        if cursor:
            cursor.close()
        flash(f"Error deleting document: {str(e)}", "error")
    
    return redirect(url_for('documents'))

@app.route("/update_paper", methods=["POST"])
def update_paper():
    try:
        data = request.get_json()
        scopus_id = data.get("scopus_id")

        if not scopus_id:
            return jsonify({"status": "error", "message": "Missing SCOPUS_ID"}), 400

        # Fetch updated paper details
        query = f"scopus-id({scopus_id})"
        scopus_response = get_scopus_data(query)
        papers = extract_paper_details(scopus_response)


        if not papers:
            return jsonify({"status": "error", "message": f"No data found for SCOPUS_ID: {scopus_id}"}), 404

        paper = papers[0]  # Only one paper expected for this SCOPUS_ID

        # Prepare database connection from the pool
        conn = db.get_connection()
        cursor = conn.cursor()

        # Update SQL - adjust this based on which fields are allowed to be updated
        update_sql = """
            UPDATE papers
            SET Title=%s,
                Authors=%s,
                `Author IDs`=%s,
                Abstract=%s,
                `Cover Date`=%s,
                `Publication Name`=%s,
                DOI=%s,
                `Subject Classification`=%s,
                `Affiliation Names`=%s
            WHERE SCOPUS_ID=%s
        """

        update_values = (
            paper.get("Title"),
            list_to_str(paper.get("Authors")),
            list_to_str(paper.get("Author IDs")), 
            paper.get("Abstract"),
            paper.get("Cover Date"),
            paper.get("Publication Name"),
            paper.get("DOI"),
            paper.get("Subject Classification"),
            paper.get("Affiliation Names"),
            scopus_id
        )


        cursor.execute(update_sql, update_values)
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({"status": "success", "message": f"Document {scopus_id} updated."})

    except Exception as e:
        logging.exception("❌ Unexpected error in update_paper")
        return jsonify({"status": "error", "message": f"Internal server error: {str(e)}"}), 500
    
@app.route('/export/pdf/<string:doc_id>')
def export_pdf(doc_id):
    doc = get_document_by_id(doc_id)
    if not doc:
        flash("Document not found for export.", "danger")
        return redirect(url_for('result'))

    rendered = render_template("pdf_template.html", doc=doc)

    # ✅ Explicit wkhtmltopdf path on Windows
    path_wkhtmltopdf = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
    config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)

    # Render to PDF
    pdf = pdfkit.from_string(rendered, False, configuration=config)

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={doc_id}.pdf'
    return response

@app.route('/export/csv/<string:doc_id>')
def export_csv(doc_id):
    doc = get_document_by_id(doc_id)
    if not doc:
        flash("Document not found for export.", "danger")
        return redirect(url_for('result'))

    def generate():
        yield 'Field,Value\n'
        for key, value in doc.items():
            yield f'"{key}","{str(value).replace(",", ";")}"\n'

    return Response(generate(), mimetype='text/csv',
                    headers={"Content-Disposition": f"attachment;filename={doc_id}.csv"})
def get_document_by_id(doc_id):
    try:
        connection = db.get_connection()
        if not connection:
            logging.error("No connection available from pool.")
            return None

        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM papers WHERE SCOPUS_ID = %s", (doc_id,))
            doc = cursor.fetchone()

        connection.close()
        return doc

    except mysql.connector.Error as e:
        logging.error(f"MySQL error while retrieving document {doc_id}: {e}")
        return None

    except Exception as e:
        logging.error(f"Unexpected error while retrieving document {doc_id}: {e}")
        return None

# === 🚀 LAUNCH ===
if __name__ == '__main__':
    app.run(debug=True)