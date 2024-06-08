import streamlit as st
import hashlib
import sqlite3
import requests
import yaml
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.errors import GoogleAdsException
from st_aggrid import AgGrid, GridOptionsBuilder

# Function to load config from a yaml file
def load_config(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

# ---------------------------------------------------------------------------------------------------------------------------------------- #
# Main function
# ---------------------------------------------------------------------------------------------------------------------------------------- #
# Define the main function to render the dashboard interface
def main():
    # Set page title and favicon
    st.set_page_config(page_title="Social Media Ads Dashboard", page_icon=":bar_chart:")

    # Load config
    config = load_config('meta_ads.yaml')

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
        show_dashboard(config, conn)
    else:
        show_login(conn)

    conn.close()

# ---------------------------------------------------------------------------------------------------------------------------------------- #
# Login/register and dashboard functions
# ---------------------------------------------------------------------------------------------------------------------------------------- #
def show_dashboard(config, conn):
    # Define navigation options
    pages = {
        "Dashboard Overview": show_dashboard_overview,
        "Meta Ads Reporting": lambda: show_meta_ads_reporting(config),
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

# ---------------------------------------------------------------------------------------------------------------------------------------- #
# Meta Facebook Ads
# ---------------------------------------------------------------------------------------------------------------------------------------- #
# Function to render Meta Ads reporting section
def show_meta_ads_reporting(config):
    st.header("Meta Ads Reporting")
    st.sidebar.title("Configuration")
    access_token = st.sidebar.text_input("Enter Facebook Access Token", value=config.get('access_token', ''))
    
    if access_token:
        st.write("Fetching data from Facebook API...")
        data = get_facebook_data(access_token)
        df = parse_facebook_data(data)
        
        if not df.empty:
            st.write("### Ad Accounts Data")
            fig_table = go.Figure(data=[go.Table(
                header=dict(values=list(df.columns),
                            fill_color='paleturquoise',
                            align='left'),
                cells=dict(values=[df[col] for col in df.columns],
                           fill_color='lavender',
                           align='left'))
            ])
            st.plotly_chart(fig_table)
            
            st.write("### Aggregated Metrics")
            agg_metrics = df[['Clicks', 'Impressions', 'Spend']].sum()
            st.write(f"**Total Clicks:** {agg_metrics['Clicks']}")
            st.write(f"**Total Impressions:** {agg_metrics['Impressions']}")
            st.write(f"**Total Spend:** ${agg_metrics['Spend']:.2f}")

            st.write("### Clicks Over Time")
            fig_clicks = px.line(df, x='Date Start', y='Clicks', title='Clicks Over Time')
            st.plotly_chart(fig_clicks)
            
            st.write("### Impressions Over Time")
            fig_impressions = px.line(df, x='Date Start', y='Impressions', title='Impressions Over Time')
            st.plotly_chart(fig_impressions)
            
            st.write("### Spend Over Time")
            fig_spend = px.line(df, x='Date Start', y='Spend', title='Spend Over Time')
            st.plotly_chart(fig_spend)

            st.write("### CPC Over Time")
            fig_cpc = px.line(df, x='Date Start', y='CPC', title='CPC Over Time')
            st.plotly_chart(fig_cpc)
            
            st.write("### CPM Over Time")
            fig_cpm = px.line(df, x='Date Start', y='CPM', title='CPM Over Time')
            st.plotly_chart(fig_cpm)

            st.write("### CPP Over Time")
            fig_cpp = px.line(df, x='Date Start', y='CPP', title='CPP Over Time')
            st.plotly_chart(fig_cpp)
            
            st.write("### CTR Over Time")
            fig_ctr = px.line(df, x='Date Start', y='CTR', title='CTR Over Time')
            st.plotly_chart(fig_ctr)
        else:
            st.error("No data available to display.")
    else:
        st.warning("Please enter your Facebook Access Token to see the data.")

# Function to get the Facebook data through API requests
def get_facebook_data(access_token):
    url = "https://graph.facebook.com/v19.0/me"
    params = {
        'fields': 'adaccounts{business_name,name,end_advertiser_name,insights{campaign_name,clicks,cpc,cpm,cpp,ctr,impressions,spend}}',
        'access_token': access_token
    }
    response = requests.get(url, params=params)
    return response.json()

# Function to parse the Facebook data
def parse_facebook_data(data):
    ad_accounts = data.get('adaccounts', {}).get('data', [])
    parsed_data = []
    for account in ad_accounts:
        business_name = account.get('business_name', '')
        account_name = account.get('name', '')
        account_id = account.get('id', '')
        end_advertiser_name = account.get('end_advertiser_name', '')
        insights = account.get('insights', {}).get('data', [])
        
        for insight in insights:
            parsed_data.append({
                'Business Name': business_name,
                'Account Name': account_name,
                'Account ID': account_id,
                'End Advertiser Name': end_advertiser_name,
                'Clicks': int(insight.get('clicks', 0)),
                'CPC': float(insight.get('cpc', 0)),
                'CPM': float(insight.get('cpm', 0)),
                'CPP': float(insight.get('cpp', 0)),
                'CTR': float(insight.get('ctr', 0)),
                'Impressions': int(insight.get('impressions', 0)),
                'Spend': float(insight.get('spend', 0)),
                'Date Start': insight.get('date_start', ''),
                'Date Stop': insight.get('date_stop', '')
            })
    return pd.DataFrame(parsed_data)

# ---------------------------------------------------------------------------------------------------------------------------------------- #
# Google Ads
# ---------------------------------------------------------------------------------------------------------------------------------------- #
# Define the function to make the Google API request
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
