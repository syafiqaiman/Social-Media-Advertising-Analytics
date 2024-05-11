import streamlit as st
import requests

from google.ads.googleads.client import GoogleAdsClient
from google.ads.googleads.errors import GoogleAdsException

# Define the main function to render the dashboard interface
def main():
    # Set page title and favicon
    st.set_page_config(page_title="Social Media Ads Dashboard", page_icon=":bar_chart:")

    # Render the header section
    st.title("Social Media Ads Analytics Dashboard")
    st.sidebar.title("Navigation")

    # Define navigation options
    pages = {
        "Dashboard Overview": show_dashboard_overview,
        "Meta Ads Reporting": show_meta_ads_reporting,
        "Google Ads Reporting": show_google_ads_reporting,
        "User Profile": show_user_profile,
        "Logout": logout
    }

    # Render navigation sidebar
    selected_page = st.sidebar.radio("Go to", list(pages.keys()))

    # Display the selected page content
    pages[selected_page]()

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

# Function to handle user logout
def logout():
    # Add code to clear user session and redirect to login page
    st.write("Logout successful")

# Execute the main function
if __name__ == "__main__":
    main()
