import streamlit as st
import hashlib
import sqlite3
import requests

from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.errors import GoogleAdsException

# Define the main function to render the dashboard interface
def main():
    # Set page title and favicon
    st.set_page_config(page_title="Social Media Ads Dashboard", page_icon=":bar_chart:")

    # Database connection
    conn = sqlite3.connect('database/users.db')
    c = conn.cursor()

    # Create users table if it does not exist
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
    conn.commit()

    # Check if the user is logged in
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    if st.session_state.logged_in:
        st.sidebar.title(f"Welcome, {st.session_state.username.title()}!")
        st.sidebar.button("Logout", on_click=logout)
        show_dashboard(conn)
    else:
        show_login(conn)

    conn.close()

def show_dashboard(conn):
    # Define navigation options
    pages = {
        "Dashboard Overview": show_dashboard_overview,
        "Meta Ads Reporting": show_meta_ads_reporting,
        "Google Ads Reporting": show_google_ads_reporting,
        "User Profile": show_user_profile
    }

    if st.session_state.role == 'admin':
        pages["User Management"] = show_user_management

    # Render navigation sidebar
    selected_page = st.sidebar.radio("Go to", list(pages.keys()))
    pages[selected_page]()

def show_login(conn):
    st.title("Login & Registration")

    # Tabs for Login and Registration
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login", key="login_button"):
            login_user(conn, login_username, login_password)

    with tab2:
        st.subheader("Register")
        register_username = st.text_input("Username", key="register_username")
        register_password = st.text_input("Password", type="password", key="register_password")
        register_password_confirm = st.text_input("Confirm Password", type="password", key="register_password_confirm")
        register_role = st.selectbox("Role", ["Client", "Admin"], key="register_role")
        if st.button("Register", key="register_button"):
            if register_password == register_password_confirm:
                register_user(conn, register_username, register_password, register_role)
            else:
                st.warning("Passwords do not match.")

def register_user(conn, username, password, role):
    c = conn.cursor()
    hashed_password = hash_password(password)
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
        conn.commit()
        st.success("User registered successfully!")
        st.experimental_rerun()
    except sqlite3.IntegrityError:
        st.warning("Username already exists.")

def login_user(conn, username, password):
    c = conn.cursor()
    hashed_password = hash_password(password)
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = c.fetchone()
    if user:
        st.session_state.logged_in = True
        st.session_state.username = username
        st.session_state.role = user[3]  # Assuming role is the 4th column
        st.success("Logged in successfully!")
        st.experimental_rerun()
    else:
        st.error("Invalid username or password.")

def logout():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.experimental_rerun()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to render dashboard overview section
def show_dashboard_overview():
    st.header("Dashboard Overview")
    # Add code to display summary metrics and charts

# Define the function to make the API request
def get_facebook_data(access_token):
    url = "https://graph.facebook.com/v19.0/me"
    params = {
        'fields': 'adaccounts{business_name,name,end_advertiser_name,insights{campaign_name,clicks,cpc,cpm,cpp,ctr,impressions,spend}}',
        'access_token': access_token
    }
    response = requests.get(url, params=params)
    return response.json()    

# Function to render Meta Ads reporting section
def show_meta_ads_reporting():
    st.header("Meta Ads Reporting")
    st.info("Please enter a valid Access Token.")
    # Add code to display Meta Ads analytics
    # Input access token
    st.sidebar.title("Configuration")
    access_token = st.sidebar.text_input("Enter Facebook Access Token")
    
    # Check if access token is provided
    if access_token:
        # Make API request when access token is provided
        st.write("Fetching data from Facebook API...")
        data = get_facebook_data(access_token)
        
        # Display the response JSON
        st.write("Response from Facebook API:")
        st.json(data)

def get_campaigns(client, customer_id):
    ga_service = client.get_service("GoogleAdsService")

    query = """
        SELECT
          campaign.id,
          campaign.name
        FROM campaign
        ORDER BY campaign.id"""

    campaigns = []

    try:
        # Issues a search request using streaming.
        stream = ga_service.search_stream(customer_id=customer_id, query=query)

        for batch in stream:
            for row in batch.results:
                campaigns.append((row.campaign.id, row.campaign.name))

    except GoogleAdsException as ex:
        st.error(
            f'Request with ID "{ex.request_id}" failed with status '
            f'"{ex.error.code().name}" and includes the following errors:'
        )
        for error in ex.failure.errors:
            st.error(f'Error with message "{error.message}".')
            if error.location:
                for field_path_element in error.location.field_path_elements:
                    st.error(f"On field: {field_path_element.field_name}")
        st.stop()

    return campaigns

# Function to render Google Ads reporting section
def show_google_ads_reporting():
    st.header("Google Ads Reporting")
    # Add code to display Google Ads analytics
    st.sidebar.title("Configuration")
    customer_id = st.sidebar.text_input("Enter Customer ID")
    if not customer_id:
        st.info("Please enter a valid Customer ID.")
        st.stop()

    googleads_client = GoogleAdsClient.load_from_storage(version="v16")

    campaigns = get_campaigns(googleads_client, customer_id)

    if not campaigns:
        st.warning("No campaigns found.")
    else:
        st.success("Campaigns successfully retrieved.")

        st.write("### Campaigns")
        for campaign_id, campaign_name in campaigns:
            st.write(f"- ID: {campaign_id}, Name: {campaign_name}")

# Function to render user profile section
def show_user_profile():
    st.header("User Profile")
    # Add code to display and update user profile information

# Function to render user management section (admin only)
def show_user_management():
    st.header("User Management")
    # Add code to display and manage user accounts
    conn = sqlite3.connect('database/users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")
    users = c.fetchall()
    conn.close()

    if users:
        for user in users:
            st.write(f"ID: {user[0]}, Username: {user[1]}, Role: {user[2]}")
            if st.button(f"Delete {user[1]}", key=f"delete_{user[0]}"):
                delete_user(user[0])

def delete_user(user_id):
    conn = sqlite3.connect('database/users.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    st.experimental_rerun()

# Execute the main function
if __name__ == "__main__":
    main()
