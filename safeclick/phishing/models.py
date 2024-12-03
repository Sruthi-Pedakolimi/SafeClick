import pickle
import os
import re
from urllib.parse import urljoin, urlparse, parse_qs
from .custom_models import GradientBoostingClassifierFromScratch , DecisionTreeClassifierFromScratch # Your custom model class
import requests
from bs4 import BeautifulSoup

# Model loading from pickle with CustomUnpickler
class CustomUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Ensure you're loading the right class based on the name
        if name=='DecisionTreeClassifierFromScratch':
            return DecisionTreeClassifierFromScratch
        if name == "GradientBoostingClassifierFromScratch":
            return GradientBoostingClassifierFromScratch
        return super().find_class(module, name)

# Path to your model
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GB_MODEL_PATH = os.path.join(BASE_DIR, 'custom_gradient_booting_model.pkl')

# Check if the model file exists
print(f"Model path: {GB_MODEL_PATH}")
if not os.path.exists(GB_MODEL_PATH):
    raise Exception("Model file does not exist!")

try:
    with open(GB_MODEL_PATH, 'rb') as file:
        best_model = CustomUnpickler(file).load()
        print(f"Model loaded successfully: {type(best_model)}")
except Exception as e:
    print(f"Error loading the model: {e}")
    best_model = None
def extract_features(url):
    # Parse the URL
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""
    at_symbol = 1 if '@' in url else 0
    
    # FakeLinkInStatusBar heuristic: look for 'javascript' or 'redirect' in the URL or query
    fake_link_in_status_bar = 1 if 'javascript' in url or 'redirect' in url else 0
    
    # Define branded names (example list, can be expanded)
    branded_names = ['google', 'facebook', 'paypal', 'amazon', 'microsoft']
    
    # If the URL contains both HTTPS and "www", mark it as safe before checking for brand
    if parsed_url.scheme == "https" and 'www' in hostname:
        embedded_brand_name = False  # Mark as safe if it has both https and www
    else:
        # Check if the hostname contains a branded name
        embedded_brand_name = any(brand in hostname.lower() for brand in branded_names)
    
    # Extract individual features
    features = [
        hostname.count('.'),
        hostname.count('.') - 1 if hostname.count('.') > 1 else 0,
        path.count('/'),
        len(url),
        url.count('-'),
        hostname.count('-'),
        url.count('~'),
        url.count('_'),
        url.count('%'),
        len(parse_qs(query)),
        query.count('&'),
        sum(c.isdigit() for c in url),
        1 if parsed_url.scheme != 'https' else 0,
        1 if is_random_string(hostname) else 0,
        1 if is_ip_address(hostname) else 0,
        1 if 'example' in hostname else 0,  # Replace 'example' with actual domain
        1 if 'example' in path else 0,  # Replace 'example' with actual domain
        len(hostname),
        len(path),
        len(query),
        count_sensitive_words(url),
        embedded_brand_name,  # Flag as unsafe if branded name is found
        pct_ext_hyperlinks(url),
        pct_ext_resource_urls(url),
        is_external_favicon(url),
        insecure_forms(url),
        relative_form_action(url),
        ext_form_action(url),
        abnormal_form_action(url),
        pct_null_self_redirect_hyperlinks(url),
        frequent_domain_name_mismatch(url),
        right_click_disabled(url),
        pop_up_window(url),
        submit_info_to_email(url),
        iframe_or_frame(url),
        missing_title(url),
        images_only_in_form(url),
        hostname.count('.') - 1 if hostname.count('.') > 1 else 0,
        len(url),
        pct_ext_resource_urls_rt(url),
        abnormal_ext_form_action_rt(url),
        ext_meta_script_link_rt(url),
        0,  # PctExtNullSelfRedirectHyperlinksRT
        url.count('#'),
        path.count('//'),
        fake_link_in_status_bar,
        at_symbol,
    ]

    print("Extracted Features (Dict):", features)
    return features


def ext_meta_script_link_rt(url):
    try:
        # Send request to get the page content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all external meta, script, and link tags
        meta_tags = soup.find_all('meta', attrs={'http-equiv': 'Content-Security-Policy', 'src': True})
        script_tags = soup.find_all('script', src=True)
        link_tags = soup.find_all('link', href=True)

        external_tags = 0
        base_domain = urlparse(url).netloc

        # Check if meta tags, scripts, or links point to external resources
        external_tags += sum(1 for tag in meta_tags if base_domain not in tag.get('src', ''))
        external_tags += sum(1 for script in script_tags if base_domain not in script['src'])
        external_tags += sum(1 for link in link_tags if base_domain not in link['href'])

        return external_tags  # Return the number of external resources in meta, script, and link tags

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if an error occurs

def abnormal_ext_form_action_rt(url):
    try:
        # Send request to get the page content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all form tags
        forms = soup.find_all('form')

        external_forms = 0
        base_domain = urlparse(url).netloc

        # Check form actions
        for form in forms:
            action = form.get('action')
            if action:
                parsed_action = urlparse(action)
                if parsed_action.netloc and parsed_action.netloc != base_domain:
                    external_forms += 1

        return external_forms  # Number of forms with external actions

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if an error occurs

def pct_ext_resource_urls_rt(url):
    try:
        # Send request to get the page content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all external resources (images, scripts, and styles)
        img_tags = soup.find_all('img', src=True)
        script_tags = soup.find_all('script', src=True)
        link_tags = soup.find_all('link', href=True)

        # Get the total number of resources (images, scripts, styles)
        total_resources = len(img_tags) + len(script_tags) + len(link_tags)

        # Count the number of external resources
        external_resources = 0
        base_domain = urlparse(url).netloc

        # Count external images
        external_resources += sum(1 for img in img_tags if base_domain not in img['src'])

        # Count external scripts
        external_resources += sum(1 for script in script_tags if base_domain not in script['src'])

        # Count external stylesheets
        external_resources += sum(1 for link in link_tags if base_domain not in link['href'])

        if total_resources == 0:
            return 0  # If no resources, return 0
        
        pct_ext_resources = (external_resources / total_resources) * 100
        return pct_ext_resources

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if an error occurs



def pct_ext_hyperlinks(url):
    try:
        # Send a request to the URL and get the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all anchor tags in the page
        anchor_tags = soup.find_all('a', href=True)

        # Count total links and external links
        total_links = len(anchor_tags)
        external_links = 0

        # Get the base domain of the current URL (to check if links are internal or external)
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc

        # Iterate over all anchor tags and check if the link is external
        for anchor in anchor_tags:
            link = anchor['href']
            # If the link is a relative URL, consider it as internal
            if link.startswith('http') or link.startswith('www'):
                # If the link is external
                if base_domain not in link:
                    external_links += 1

        # Calculate the percentage of external links
        if total_links == 0:
            return 0  # If there are no links, return 0

        pct_ext_hyperlinks = (external_links / total_links) * 100
        return pct_ext_hyperlinks

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if an error occurs (e.g., network error, invalid URL)

# Example usage
url = 'https://example.com'  # Replace with the URL you want to test
percentage = pct_ext_hyperlinks(url)
print(f"Percentage of external hyperlinks: {percentage}%")

def pct_ext_resource_urls(url):
    try:
        # Send a request to the URL and get the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all tags that contain src or href attributes (resources)
        resource_tags = soup.find_all(['img', 'script', 'link', 'iframe'], src=True) + soup.find_all(['link', 'script'], href=True)

        # Count total resources and external resources
        total_resources = len(resource_tags)
        external_resources = 0

        # Get the base domain of the current URL (to check if resources are internal or external)
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc

        # Iterate over all resource tags and check if the resource is external
        for tag in resource_tags:
            # For 'img', 'script', 'iframe', check src
            src = tag.get('src') or tag.get('href')
            
            # If the resource is external
            if src.startswith('https') or src.startswith('www'):
                if base_domain not in src:
                    external_resources += 1

        # Calculate the percentage of external resources
        if total_resources == 0:
            return 0  # If there are no resources, return 0

        pct_ext_resource_urls = (external_resources / total_resources) * 100
        return pct_ext_resource_urls

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if an error occurs (e.g., network error, invalid URL)

# Example usage
url = 'https://example.com'  # Replace with the URL you want to test
percentage = pct_ext_resource_urls(url)
print(f"Percentage of external resources: {percentage}%")



def is_external_favicon(url):
    try:
        # Send a request to the URL and get the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the <link> tag with rel="icon" (favicon)
        favicon_tag = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')

        # If favicon tag is found
        if favicon_tag and 'href' in favicon_tag.attrs:
            favicon_url = favicon_tag['href']

            # Check if favicon URL is external
            if favicon_url.startswith('https') or favicon_url.startswith('www'):
                return 1  # External favicon
            else:
                # If it's a relative URL, resolve it to check if it becomes external
                base_url = urlparse(url).scheme + "://" + urlparse(url).hostname
                full_url = urljoin(base_url, favicon_url)
                if base_url not in full_url:
                    return 1  # External favicon
            
        # If no external favicon or no favicon tag found, return 0
        return 0
    
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if there's an error (e.g., network error)



def insecure_forms(url):
    try:
        # Send a request to the URL and get the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms on the page
        forms = soup.find_all('form')

        for form in forms:
            # Check the action attribute of the form
            action = form.get('action', '')
            
            # If the action starts with 'http://', consider it insecure
            if action.startswith('http://'):
                return 1  # Insecure form

        return 0  # No insecure forms found
    
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if there's an error (e.g., network error)



def relative_form_action(url):
    try:
        # Send a request to the URL and get the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms on the page
        forms = soup.find_all('form')

        for form in forms:
            # Check the action attribute of the form
            action = form.get('action', '')

            # If the action is a relative URL (starts with '/')
            if action.startswith('/'):
                return 1  # Relative form action found

        return 0  # No relative form action found

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if there's an error (e.g., network error)



def ext_form_action(url):
    try:
        # Send a request to the URL and get the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms on the page
        forms = soup.find_all('form')

        for form in forms:
            # Check the action attribute of the form
            action = form.get('action', '')

            # If the action is an absolute URL (starts with 'http://', 'https://')
            if action.startswith('http://') or action.startswith('https://'):
                return 1  # External form action found

        return 0  # No external form action found

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if there's an error (e.g., network error)



def abnormal_form_action(url):
    try:
        # Send a request to the URL and get the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the page content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms on the page
        forms = soup.find_all('form')

        suspicious_keywords = ['login', 'account', 'secure', 'password', 'update']

        for form in forms:
            # Get the action attribute of the form
            action = form.get('action', '')

            # If the action is relative, make it absolute
            if not action.startswith(('http://', 'https://')):
                action = urljoin(url, action)

            # Check if the action URL contains suspicious keywords
            if any(keyword in action.lower() for keyword in suspicious_keywords):
                return 1  # Abnormal form action detected

            # Optionally: Check for known suspicious domains (if applicable)
            parsed_action_url = urlparse(action)
            suspicious_domains = ['example.com', 'phishing.com', 'malicious-site.com']
            if parsed_action_url.netloc in suspicious_domains:
                return 1  # Abnormal domain found in form action

        return 0  # No abnormal form action found

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if there's an error (e.g., network error)


# Helper functions for features
def is_random_string(hostname):
    return bool(re.search(r'[a-zA-Z0-9]{10,}', hostname))

def is_ip_address(hostname):
    try:
        ip = hostname.split(':')[0]
        return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip)) or bool(re.match(r'^[a-fA-F0-9:]+$', ip))
    except:
        return False

def count_sensitive_words(url):
    sensitive_keywords = ['login', 'account', 'verify', 'secure', 'password', 'update']
    return sum([1 for word in sensitive_keywords if word in url.lower()])

def is_embedded_brand_name(url):
    # Known brands (extend as needed)
    known_brands = ['google', 'facebook', 'paypal', 'amazon', 'microsoft']
    
    # Check if both 'https' and 'www' are in the URL
    if "https" in url and 'www' in url:
        return False  # If the URL has both https and www, consider it safe even if it contains a brand
    
    # Otherwise, check for branded names
    return any(brand in url.lower() for brand in known_brands)

# Feature extraction functions
def pct_null_self_redirect_hyperlinks(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        anchor_tags = soup.find_all('a', href=True)
        total_links = len(anchor_tags)
        self_redirect_links = 0

        for anchor in anchor_tags:
            link = anchor['href']
            if link and url in link:
                self_redirect_links += 1

        if total_links == 0:
            return 0

        return (self_redirect_links / total_links) * 100
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0


def frequent_domain_name_mismatch(url):
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc

    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        count = soup.prettify().count(domain_name)

        if count > 5:
            return 1
        return 0
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0


def right_click_disabled(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        scripts = soup.find_all('script')
        for script in scripts:
            if 'oncontextmenu' in script.text:
                return 1  # Right-click disabled
        return 0
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0


def pop_up_window(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        scripts = soup.find_all('script')
        for script in scripts:
            if 'window.open' in script.text:
                return 1  # Pop-up detected
        return 0
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0


def submit_info_to_email(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form', action=True)
        for form in forms:
            action_url = form.get('action')
            if '@' in action_url:
                return 1  # Suspicious email submission detected
        return 0
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0


def iframe_or_frame(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        if soup.find_all('iframe') or soup.find_all('frame'):
            return 1  # iframe or frame detected
        return 0  # No iframe or frame detected
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0


def missing_title(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        title = soup.title
        if title is None or not title.string.strip():
            return 1  # Missing title
        return 0  # Title found
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0
    from bs4 import BeautifulSoup
import requests

# Function to check if a form contains only images
def images_only_in_form(url):
    try:
        # Send request to get the page content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all form elements in the page
        forms = soup.find_all('form')

        for form in forms:
            # Find all image tags in the form
            img_tags = form.find_all('img')
            
            # Check if there are no other form elements (e.g., input, button)
            form_elements = form.find_all(['input', 'button', 'select', 'textarea'])
            
            if len(img_tags) > 0 and len(form_elements) == 0:
                return 1  # The form contains only images, which is suspicious

        return 0  # No form contains only images

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return 0  # Return 0 if an error occurs (e.g., network issues)
