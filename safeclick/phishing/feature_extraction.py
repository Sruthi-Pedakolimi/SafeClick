import re
import tldextract
import socket
from bs4 import BeautifulSoup
import requests
import tldextract

def extract_features(url):
    features = {}

    # Helper function to count specific characters
    def count_characters(char, string):
        return string.count(char)

    # Feature extraction
    features['NumDots'] = count_characters('.', url)
    features['SubdomainLevel'] = len(tldextract.extract(url).subdomain.split('.'))
    features['PathLevel'] = len(re.split(r'[\\/]', url)) - 1
    features['UrlLength'] = len(url)
    features['NumDash'] = count_characters('-', url)
    features['NumDashInHostname'] = count_characters('-', tldextract.extract(url).domain)
    # features['TildeSymbol'] = count_characters('~', url)
    features['NumUnderscore'] = count_characters('_', url)
    features['NumPercent'] = count_characters('%', url)
    features['NumQueryComponents'] = count_characters('?', url)
    features['NumAmpersand'] = count_characters('&', url)
    features['NumNumericChars'] = sum(c.isdigit() for c in url)
    features['NoHttps'] = extract_no_https_feature(url)
    features['RandomString'] = int(any(c.isupper() for c in url))
    features['IpAddress'] = int(bool(re.match(r'(\d{1,3}\.){3}\d{1,3}', url)))
    # features['DomainInSubdomains'] = int(tldextract.extract(url).domain in url)
    features['DomainInPaths'] = int(tldextract.extract(url).domain in url.split('/'))
    features['HostnameLength'] = len(tldextract.extract(url).domain)
    features['PathLength'] = len('/'.join(url.split('/')[3:]))
    features['QueryLength'] = len(url.split('?')[-1]) if '?' in url else 0
    features['NumSensitiveWords'] = sum(url.lower().count(word) for word in ['secure', 'login', 'account'])
    features['EmbeddedBrandName'] = int('paypal' in url.lower() or 'google' in url.lower())

    # Additional Placeholder Features
    features['PctExtHyperlinks'] = calculate_pct_ext_hyperlinks(url)
    features['PctExtResourceUrls'] = calculate_pct_ext_resource_urls(url)
    features['ExtFavicon'] = calculate_ext_favicon(url)
    # features['AbnormalFormAction'] = calculate_abnormal_form_action(url)
    # Add other placeholders as needed
    features['InsecureForms'] = calculate_insecure_forms(url)
    features['RelativeFormAction'] = calculate_relative_form_action(url)
    features['ExtFormAction'] = calculate_ext_form_action(url)
    # features['RightClickDisabled'] = calculate_right_click_disabled(url)
    features['SubmitInfoToEmail'] = calculate_submit_info_to_email(url)
    features['IframeOrFrame'] = calculate_iframe_or_frame(url)
    features['MissingTitle'] = calculate_missing_title(url)
    # features['ImagesOnlyInForm'] = calculate_images_only_in_form(url)
    features['SubdomainLevelRT'] = calculate_subdomain_level_rt(url)
    features['UrlLengthRT'] = calculate_url_length_rt(url)
    features['PctNullSelfRedirectHyperlinks'] = calculate_pct_null_self_redirect_hyperlinks(url)
    features['FrequentDomainNameMismatch'] = calculate_frequent_domain_name_mismatch(url)
    features['PctExtResourceUrlsRT'] = calculate_pct_ext_resource_urls_rt(url)
    features['AbnormalExtFormActionR'] = calculate_abnormal_ext_form_action_r(url)
    features['ExtMetaScriptLinkRT'] = calculate_ext_meta_script_link_rt(url)
    features['PctExtNullSelfRedirectHyperlinksRT'] = calculate_pct_ext_null_self_redirect_hyperlinks_rt(url)

    return features

def extract_no_https_feature(url):
    """
    Checks whether the URL starts with HTTPS or not.
    Returns 1 if not HTTPS, otherwise 0.
    """
    return 1 if not url.lower().startswith('https://') else 0


def calculate_pct_ext_hyperlinks(url):
    """Calculate the percentage of external hyperlinks on the page."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        if not links:
            return 0
        external_links = [
            link for link in links
            if link.get('href') and not tldextract.extract(link.get('href')).domain == tldextract.extract(url).domain
        ]
        return len(external_links) / len(links)
    except:
        return 0

def calculate_pct_ext_resource_urls(url):
    """Calculate the percentage of external resource URLs (scripts, stylesheets, etc.)."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        resources = soup.find_all(['script', 'link', 'img'])
        if not resources:
            return 0
        external_resources = [
            res for res in resources
            if res.get('src') or res.get('href') and not tldextract.extract(res.get('src') or res.get('href')).domain == tldextract.extract(url).domain
        ]
        return len(external_resources) / len(resources)
    except:
        return 0

def calculate_ext_favicon(url):
    """Check if the favicon URL is external."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        if favicon and favicon.get('href'):
            favicon_domain = tldextract.extract(favicon['href']).domain
            main_domain = tldextract.extract(url).domain
            return int(favicon_domain != main_domain)
        return 0
    except:
        return 0

def calculate_abnormal_form_action(url):
    """Placeholder for detecting abnormal form actions."""
    try:

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            return 0
        abnormal_forms = [
            form for form in forms
            if form.get('action') and not url in form.get('action')  # Simple check for abnormal form action
        ]
        return len(abnormal_forms) / len(forms)
    except:
        return 0

def calculate_pct_null_self_redirect_hyperlinks(url):
    """Calculate percentage of null or self-redirecting hyperlinks.""" 
    try:
        temp_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        response = requests.get(temp_url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        if not links:
            return 0
        null_self_links = [
            link for link in links
            if not link.get('href') or link.get('href').strip() == '' or link.get('href') == '#'
        ]
        return len(null_self_links) / len(links)
    except:
        return 0

def calculate_frequent_domain_name_mismatch(url):
    """Placeholder to detect frequent domain name mismatches."""
    try:
        main_domain = tldextract.extract(url).domain
        temp_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        response = requests.get(temp_url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        if not links:
            return 0
        mismatched_links = [
            link for link in links
            if link.get('href') and tldextract.extract(link.get('href')).domain != main_domain
        ]
        return len(mismatched_links) / len(links)
    except:
        return 0

def calculate_insecure_forms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        insecure_forms = [form for form in forms if form.get('action') and not form.get('action').startswith('https://')]
        return len(insecure_forms) / len(forms) if forms else 0
    except:
        return 0

def calculate_relative_form_action(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        relative_forms = [form for form in forms if form.get('action') and not form.get('action').startswith(('http://', 'https://'))]
        return len(relative_forms) / len(forms) if forms else 0
    except:
        return 0
    
def calculate_ext_form_action(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        main_domain = tldextract.extract(url).domain
        forms = soup.find_all('form')
        external_forms = [form for form in forms if form.get('action') and main_domain not in form.get('action')]
        return len(external_forms) / len(forms) if forms else 0
    except:
        return 0
    
def calculate_right_click_disabled(url):
    try:
        response = requests.get(url, timeout=5)
        return int("contextmenu" in response.text.lower())
    except:
        return 0


def calculate_submit_info_to_email(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        email_forms = [form for form in forms if form.get('action') and 'mailto:' in form.get('action')]
        return len(email_forms) / len(forms) if forms else 0
    except:
        return 0

def calculate_iframe_or_frame(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        return int(bool(soup.find('iframe') or soup.find('frame')))
    except:
        return 0

def calculate_missing_title(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        return int(soup.title is None)
    except:
        return 0
    
def calculate_images_only_in_form(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        image_only_forms = [form for form in forms if all(input_tag.get('type') == 'image' for input_tag in form.find_all('input'))]
        return len(image_only_forms) / len(forms) if forms else 0
    except:
        return 0

def calculate_subdomain_level_rt(url):
    try:
        return 1 / (len(tldextract.extract(url).subdomain.split('.')) + 1)
    except:
        return 0

def calculate_url_length_rt(url):
    try:
        return 1 / (len(url) + 1)
    except:
        return 0

def calculate_pct_ext_resource_urls_rt(url):
    pct_ext_resource_urls = calculate_pct_ext_resource_urls(url)
    return 1 / (pct_ext_resource_urls + 1)


def calculate_abnormal_ext_form_action_r(url):
    abnormal_form_action = calculate_abnormal_form_action(url)
    return 1 / (abnormal_form_action + 1)

def calculate_ext_meta_script_link_rt(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        metas = soup.find_all('meta')
        scripts = soup.find_all('script')
        links = soup.find_all('link')
        external_resources = [
            res for res in metas + scripts + links
            if res.get('src') or res.get('href') and not tldextract.extract(res.get('src') or res.get('href')).domain == tldextract.extract(url).domain
        ]
        return len(external_resources) / (len(metas) + len(scripts) + len(links)) if (metas + scripts + links) else 0
    except:
        return 0

def calculate_pct_ext_null_self_redirect_hyperlinks_rt(url):
    pct_null_self_redirect_hyperlinks = calculate_pct_null_self_redirect_hyperlinks(url)
    return 1 / (pct_null_self_redirect_hyperlinks + 1)


