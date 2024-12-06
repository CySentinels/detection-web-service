import requests
from bs4 import BeautifulSoup
import tldextract
import re
import urllib.parse
import whois
import dns.resolver
import difflib
import collections
import string
from functools import lru_cache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# Retry mechanism for HTTP requests
session = requests.Session()
retry_strategy = Retry(
    total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

@lru_cache(maxsize=100)
def fetch_url_content(url):
    """Fetch URL content with retries and caching."""
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error for {url}: {http_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"Request error for {url}: {req_err}")
        return None

def dns_query(domain, record_type):
    """Perform DNS queries for specific record types."""
    try:
        return dns.resolver.resolve(domain, record_type)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return []

def validate_domain(domain):
    """Check legitimacy with DNS queries (A, MX, NS records)."""
    a_records = dns_query(domain, 'A')
    mx_records = dns_query(domain, 'MX')
    ns_records = dns_query(domain, 'NS')

    # Check if at least one record exists for each type
    is_valid = bool(a_records or mx_records or ns_records)
    return int(is_valid)  # Return 1 for valid, 0 otherwise

def similarity_score(a, b):
    """Compute similarity score using difflib."""
    return difflib.SequenceMatcher(None, a, b).ratio() * 100

def has_hidden_fields(soup):
    return bool(soup.find_all("input", type="hidden"))

def no_of_popups(soup):
    # Look for JavaScript functions that may indicate popups
    popup_patterns = re.compile(r"window\.open|alert\(|confirm\(|prompt\(")
    scripts = soup.find_all("script")
    return sum(1 for script in scripts if popup_patterns.search(script.get_text()))

def url_title_match_score(url, title):
    title_words = set(re.findall(r'\w+', title.lower()))
    url_words = set(re.findall(r'\w+', url.lower()))
    common_words = title_words & url_words
    return len(common_words) / len(title_words) if title_words else 0

def has_password_field(soup):
    return bool(soup.find_all("input", type="password"))

def has_copyright_info(soup):
    copyright_patterns = re.compile(r"©|&copy;|copyright", re.IGNORECASE)
    return bool(soup.find(text=copyright_patterns))

def no_of_self_redirects(soup, domain):
    links = soup.find_all("a", href=True)
    return sum(1 for link in links if domain in link["href"])

def no_of_iframes(soup):
    return len(soup.find_all("iframe"))

def obfuscation_ratio(html):
    total_chars = len(html)
    special_chars = sum(1 for c in html if not c.isalnum() and c not in string.whitespace)
    return special_chars / total_chars if total_chars else 0

def domain_title_match_score(domain, title):
    domain_parts = set(re.findall(r'\w+', domain.lower()))
    title_parts = set(re.findall(r'\w+', title.lower()))
    common_parts = domain_parts & title_parts
    return len(common_parts) / len(title_parts) if title_parts else 0

def url_char_prob(url):
    url_chars = re.sub(r'[^a-zA-Z]', '', url.lower())
    char_counts = collections.Counter(url_chars)
    total_chars = len(url_chars)
    return {char: count / total_chars for char, count in char_counts.items()}

def no_of_url_redirects(response):
    return len(response.history)

def has_submit_button(soup):
    return bool(soup.find("button", type="submit") or soup.find("input", type="submit"))

def has_external_form_submit(soup, domain):
    forms = soup.find_all("form")
    external_forms = [form for form in forms if form.get("action") and domain not in form["action"]]
    return bool(external_forms)

def char_continuation_rate(url):
    consecutive = 0
    max_consecutive = 0
    for i in range(1, len(url)):
        if url[i].isalpha() and url[i] == url[i-1]:
            consecutive += 1
            max_consecutive = max(max_consecutive, consecutive)
        else:
            consecutive = 0
    return max_consecutive / len(url) if len(url) else 0

def extract_features_v0(url):
    """Extract features from the given URL."""
    features = {}
    parsed_url = urllib.parse.urlparse(url)
    domain_info = tldextract.extract(url)
    domain = parsed_url.netloc

    # URL and domain analysis
    features['URLLength'] = len(url)
    features['DomainLength'] = len(domain_info.domain)
    features['TLDLength'] = len(domain_info.suffix)
    features['NoOfSubDomain'] = len(domain_info.subdomain.split('.'))
    features['IsDomainIP'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain_info.domain) else 0
    features['IsHTTPS'] = 1 if parsed_url.scheme == 'https' else 0

    # Character counts in URL
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')
    special_chars = re.findall(r'[^\w\s]', url)
    features['NoOfOtherSpecialCharsInURL'] = len(special_chars) - features['NoOfQMarkInURL'] - features['NoOfAmpersandInURL']

    # Ratios
    url_length = len(url)
    features['LetterRatioInURL'] = features['NoOfLettersInURL'] / url_length
    features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / url_length
    features['SpacialCharRatioInURL'] = len(special_chars) / url_length

    # TLD legitimacy and similarity scores
    features['TLDLegitimateProb'] = 0.5  # Placeholder value
    features['URLSimilarityIndex'] = similarity_score(domain_info.domain, parsed_url.path)

    # DNS-based domain legitimacy check
    features['IsDomainLegitimate'] = validate_domain(domain_info.domain)

    html = fetch_url_content(url)
    if html is None:
        print(f"Skipping {url} due to fetch error.")
        return features

    # HTML parsing with BeautifulSoup
    try:
        soup = BeautifulSoup(html, 'html.parser')
        lines = html.splitlines()
        title = soup.title.string if soup.title else ""
        response = requests.get(url)  # Used to count redirects

        features['LineOfCode'] = len(lines)
        features['LargestLineLength'] = max(len(line) for line in lines)

        features['NoOfImage'] = len(soup.find_all('img'))
        features['NoOfCSS'] = len(soup.find_all('link', {'rel': 'stylesheet'}))
        features['NoOfJS'] = len(soup.find_all('script'))

        all_links = soup.find_all('a')
        features['NoOfSelfRef'] = sum(1 for link in all_links if url in link.get('href', ''))
        features['NoOfEmptyRef'] = sum(1 for link in all_links if link.get('href') == '#')
        features['NoOfExternalRef'] = len(all_links) - features['NoOfSelfRef'] - features['NoOfEmptyRef']

        # Metadata checks
        features['HasTitle'] = 1 if soup.title else 0
        if soup.title:
            features['DomainTitleMatchScore'] = similarity_score(domain_info.domain, soup.title.text)
            features['URLTitleMatchScore'] = similarity_score(url, soup.title.text)

        features['HasFavicon'] = 1 if soup.find('link', rel='icon') else 0
        features['Robots'] = 1 if soup.find('meta', {'name': 'robots'}) else 0
        features['IsResponsive'] = 1 if soup.find('meta', {'name': 'viewport'}) else 0

        features['HasDescription'] = 1 if soup.find('meta', {'name': 'description'}) else 0
        features['HasSocialNet'] = any(net in html for net in ['facebook', 'twitter', 'instagram', 'linkedin'])
        features['HasHiddenFields'] = has_hidden_fields(soup),
        features['NoOfPopup'] = no_of_popups(soup),
        features['URLTitleMatchScore'] = url_title_match_score(url, title),
        features['HasPasswordField'] = has_password_field(soup),
        features['HasCopyrightInfo'] = has_copyright_info(soup),
        features['NoOfSelfRedirect'] = no_of_self_redirects(soup, domain),
        features['NoOfiFrame'] = no_of_iframes(soup),
        features['ObfuscationRatio'] = obfuscation_ratio(html),
        features['DomainTitleMatchScore'] = domain_title_match_score(domain, title),
        features['URLCharProb'] = 0.5, # Placeholder value
        features['NoOfURLRedirect'] = no_of_url_redirects(response),
        features['HasSubmitButton'] = has_submit_button(soup),
        features['HasExternalFormSubmit'] = has_external_form_submit(soup, domain),
        features['CharContinuationRate'] = char_continuation_rate(url)

    except Exception as e:
        print(f"Error parsing HTML content for {url}: {e}")

    return features

def extract_features(url):
    """Extract features from the given URL."""
    features = {}
    parsed_url = urllib.parse.urlparse(url)
    domain_info = tldextract.extract(url)
    domain = parsed_url.netloc

    # Basic URL features
    features['URLLength'] = len(url)
    # features['Domain'] = domain_info.domain
    features['DomainLength'] = len(domain_info.domain)
    features['IsDomainIP'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain_info.domain) else 0
    features['TLD'] = domain_info.suffix
    features['TLDLength'] = len(domain_info.suffix)
    features['NoOfSubDomain'] = len(domain_info.subdomain.split('.')) if domain_info.subdomain else 0
    features['IsHTTPS'] = 1 if parsed_url.scheme == 'https' else 0

    # URL character analysis
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')
    special_chars = re.findall(r'[^\w\s]', url)
    features['NoOfOtherSpecialCharsInURL'] = len(special_chars) - features['NoOfQMarkInURL'] - features['NoOfAmpersandInURL']

    # Ratios
    url_length = len(url)
    features['LetterRatioInURL'] = features['NoOfLettersInURL'] / url_length if url_length > 0 else 0
    features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / url_length if url_length > 0 else 0
    features['SpacialCharRatioInURL'] = len(special_chars) / url_length if url_length > 0 else 0

    # Obfuscation analysis
    obfuscated_chars = re.findall(r'%[0-9a-fA-F]{2}', url)
    features['HasObfuscation'] = 1 if obfuscated_chars else 0
    features['NoOfObfuscatedChar'] = len(obfuscated_chars)
    features['ObfuscationRatio'] = features['NoOfObfuscatedChar'] / url_length if url_length > 0 else 0

    # URL similarity and continuation
    features['URLSimilarityIndex'] = similarity_score(domain_info.domain, parsed_url.path)
    features['CharContinuationRate'] = char_continuation_rate(url)
    features['URLCharProb'] = 0.9 # Placeholder - could be implemented
    features['TLDLegitimateProb'] = 0.9  # Placeholder - could be implemented with a TLD legitimacy database

    html = fetch_url_content(url)
    if html is None:
        return features

    try:
        soup = BeautifulSoup(html, 'html.parser')
        lines = html.splitlines()
        title = soup.title.string if soup.title else ""
        response = requests.get(url)

        # HTML content features
        # features['LineOfCode'] = len(lines)
        features['LargestLineLength'] = max(len(line) for line in lines)
        features['HasTitle'] = 1 if soup.title else 0
        features['DomainTitleMatchScore'] = domain_title_match_score(domain, title)
        features['URLTitleMatchScore'] = url_title_match_score(url, title)

        # Meta features
        features['HasFavicon'] = 1 if soup.find('link', rel='icon') else 0
        features['Robots'] = 1 if soup.find('meta', {'name': 'robots'}) else 0
        features['IsResponsive'] = 1 if soup.find('meta', {'name': 'viewport'}) else 0
        features['HasDescription'] = 1 if soup.find('meta', {'name': 'description'}) else 0

        # Resource counts
        # features['NoOfImage'] = len(soup.find_all('img'))
        features['NoOfCSS'] = len(soup.find_all('link', {'rel': 'stylesheet'}))
        # features['NoOfJS'] = len(soup.find_all('script'))

        # Link analysis
        all_links = soup.find_all('a')
        features['NoOfSelfRef'] = sum(1 for link in all_links if url in link.get('href', ''))
        features['NoOfEmptyRef'] = sum(1 for link in all_links if link.get('href') == '#')
        features['NoOfExternalRef'] = len(all_links) - features['NoOfSelfRef'] - features['NoOfEmptyRef']

        # Security features
        features['NoOfURLRedirect'] = len(response.history)
        features['NoOfSelfRedirect'] = no_of_self_redirects(soup, domain)
        features['NoOfPopup'] = no_of_popups(soup)
        features['NoOfiFrame'] = no_of_iframes(soup)
        features['HasExternalFormSubmit'] = 1 if has_external_form_submit(soup, domain) else 0
        features['HasSubmitButton'] = 1 if has_submit_button(soup) else 0
        features['HasHiddenFields'] = 1 if has_hidden_fields(soup) else 0
        features['HasPasswordField'] = 1 if has_password_field(soup) else 0
        features['HasCopyrightInfo'] = 1 if has_copyright_info(soup) else 0

        # Content analysis
        features['HasSocialNet'] = 1 if re.search(r'facebook|twitter|instagram|linkedin', html, re.I) else 0
        features['Bank'] = 1 if re.search(r'bank|banking|credit|debit', html, re.I) else 0
        features['Pay'] = 1 if re.search(r'payment|pay|transaction', html, re.I) else 0
        features['Crypto'] = 1 if re.search(r'crypto|bitcoin|ethereum|wallet', html, re.I) else 0

    except Exception as e:
        print(f"Error parsing HTML content for {url}: {e}")

    return features

def process_urls(urls):
    """Process multiple URLs in parallel using ThreadPoolExecutor."""
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(extract_features, url): url for url in urls}
        results = []
        for future in as_completed(futures):
            url = futures[future]
            try:
                features = future.result()
                print(f"Features for {url}: {features}")
                results.append(features)
            except Exception as e:
                print(f"Error processing {url}: {e}")
    return results


# urls = ["http://0wa477gswk848mbc7309gd.mattsenior1.repl.co", "http://3dcloud.co.uk/wp-content/themes/twentynineteen/fonts/jw/rakne/Process/pc/7e7dbfdec8a5394fc27a6cdc9a3d", "http://3dcloud.co.uk/wp-content/themes/twentynineteen/fonts/jw/rakne/Process/pc/7e7dbfdec8a5394fc27a6cdc9a3d/cardinfof4e.php", "https://3lnbwozouaaxkmrmqmtyxnhrosmfudwfyetiwmje.filesusr.com/html/46d2e9_6a7c2030c9ba4a404a357027e732be3f.html", "http://8c4d591d.ithemeshosting.com.php73-39.lan3-1.websitetestlink.com/mpp/signin/5cd3/websrc", "http://188.128.202.35.bc.googleusercontent.com", "https://687f7cce0d3669684.temporary.link/s/update.php", "http://4666.co.kr/webpage", "http://27976a9732.nxcli.net/account/fb.php", "http://27976a9732.nxcli.net/account", "https://131425.000webhostapp.com", "http://21-123-2.vasdasdvvvv.repl.co", "http://aapartments.com.ua/themes/zimbra/ZimbraWebSignIn.htm?email=oem@spal.it", "http://about-ads-microsoft-com.o365.frc.skyfencenet.com", "https://accessboaonlines.com/here/signin.php", "http://account-device-register.com", "http://acoustic.how-toplayguitar-today.com/bernesepups.com/wp-content/themes/made%20in%20china/made-in-chin-new%20dd", "http://activadigital-1.com", "https://adminbase2.000webhostapp.com/webmail.presidencia.gub.uy.html", "http://adsbusinessaccountcreditscoupon.com", "http://adxpklseomcjptymnzelzzdstg-dot-polished-shore-301017.uk.r.appspot.com", "https://agentwealthsuccess.com/wp-admin/users/office-2020", "http://aggiornamentosicuro.com", "https://agitated-swanson-2400de.netlify.app", "http://albaitalshamy.com/3ed/suntrust/suntrust", "https://alert-new-hali.com", "http://alert-unknown-payee.live/Login.php", "https://alhazmico.com/assets/fonts/codropsicons/METRO/METRO", "http://alliance4consumersusa.org/enroll/ver.pdf.html", "https://amazon-osaka.xyz", "http://anbkstvpokpqrdklfaoobjugkq-dot-polished-shore-301017.uk.r.appspot.com", "http://anozlnd.com/welcome-intro.app.php", "http://anozlnd.com/personal-details.app.php?stage=step2&webssl=2tV3ipFwdWm5elrCJNjYLILgT&DMO", "http://anvietlong.com/Login/Secure_Zone/Confirm/websc_signin", "http://aphomes.in/img/clients", "http://api.cargomanager.io", "http://app11.easysendyapp.com/orangeclients", "https://archiepba.com/cade/z0n51-paypal/60339ae3373bfb1/login.php", "https://asfysfgqlassxrzotawcqmaqqe-dot-polished-shore-301017.uk.r.appspot.com", "https://assist-personal.com/hsbc", "https://authorise-mydetails.com/lloyds/Login.php", "https://authorise-mypayee.live/hsbc", "https://auth-revoke.com/hsbc", "http://autodex53.xyz/tttttt/a/a/a/login.php", "https://averagesustain.com/Arica/Anderson", "http://avisoperu.com/clientes", "http://awwww.palpay-ltd.xyz/loginuser.php", "http://axomonline.com/ln/Exitkorea/upload", "http://backoffice.dhlthprivilege.com/auth", "http://baithi1.xyz", "http://bajatel.mx/wp-content/themes/twentynineteen/js/i2k/bizmail.php?email=&.rand=13vqcr8bp0gud&lc=1033&id=64855&mkt=en-us&cbcxt=mai&snsc=1", "https://bancaporinternet-interbank.movilaplicativo.com/05948448/personas", "https://bankgbzbhrvnlbtblweejpcdts-dot-polished-shore-301017.uk.r.appspot.com", "http://batterybazaaronline.com/library/js/jp/8837fd617f25135ec606a143c8306ec0/home.php", "http://batterybazaaronline.com/library/js/jp/e86717a0e35d3559b53320bf81c007db?cmd=_identifier_demarrer_id=4566973159090+_time:fri,dec,18,2020-1:01am", "http://batterybazaaronline.com/library/js/jp/aa05a96b065cb1fe8aecb7786188633f/home.php", "http://batterybazaaronline.com/library/js/jp/9adc86c11b30253d9d12d7505d96d233?cmd=_identifier_demarrer_id=9064546301961+_time:thu,dec,17,2020-4:00am", "http://batterybazaaronline.com/library/js/jp/e25045735cec96c5bb98d7adba51ea02?cmd=_identifier_demarrer_id=3614983125590+_time:fri,dec,18,2020-12:20am", "http://batterybazaaronline.com/library/js/jp", "https://bbdjdkimmd34.000webhostapp.com/verification24.html", "http://bbdjdkimmd34.000webhostapp.com", "https://bbdjdkimmd34.000webhostapp.com/verification22.html", "https://bbdjdkimmd34.000webhostapp.com/ondetverifier.php", "https://bbdjdkimmd34.000webhostapp.com/verification23.html", "https://belgarden.it/plugins/to/TO/admin@example.com", "https://believable16442130.blob.core.windows.net/zilpah184585361121/login.html?mlajob=M77x8UyrtVexRIm6bdWa7K1Moa&gnq=iA5rRmA6yuEl3lXk&kdfa=DtwnjOaMkytrQbvgi&fizwpfrss=EcL9ZLCC1gbHjhJFwYHGAj4&uzcepzpbp=3gVjGUYqKWhOAIsQbNCT7g2fBr&sjgeci=xQUojCT3MfZCsq5&lrcsxxwd=KmNP4Ge2x77HFA5FyrPRO4Z", "http://bergabung18.ezua.com", "http://bigevilbooleanlogic--five-nine.repl.co", "http://billetterie.angers-sco.dspsport.com/Dsp/web/site/packages/Payment/info3Dsecure.htm", "https://bir365.com", "http://bitesizedbreakablescientificcomputing--five-nine.repl.co", "http://bitmoj1tweaks.000webhostapp.com", "http://bitphi.000webhostapp.com/login.html", "http://blendercoin.000webhostapp.com/index.html", "http://blocked-payments.com/hsbc/reg", "http://blocked-payments.com/hsbc/reg/spec", "http://blocked-payments.com/hsbc/spe", "https://bluetickserviceinnnstagram4409x.ga", "http://blvdamjkosvmzxaj-dot-owaonk399399393.uk.r.appspot.com", "https://bonniewindersattorney.com/doc", "http://bramblebaybowlsclub.com.au/F0b4h5d88bb406e23/?xra=arx&xav=cm9iZXJ0ZWFkZHlAYmVsbHNvdXRoLm5ldA==", "http://bramblebaybowlsclub.com.au/X08fg4he5e915180c/?xra=arx&xav=anVsaWUuYXVjb2luQGludHJhbG94LmNvbQ==", "http://brave-poincare-c1bcee.netlify.app", "http://brightonhomes.in/img/web/Webmail/index.php?email=alfonso_carrera@palletways.com", "https://brotherequinox.com/owa2/index.php?error=1", "https://brusselsarport.be/umglbk2b45c017jq", "https://bshdnekun.bdhnekwhjsdl.shop", "http://btbrpfknucemdinwytnkxrcilu-dot-polished-shore-301017.uk.r.appspot.com", "http://bulkydeafeningprofessional--five-nine.repl.co", "http://burdine-anderson.com.bitqprepare.xyz/document/permission", "https://bvhoncsrywanaofgtodzsuzlwb-dot-polished-shore-301017.uk.r.appspot.com", "https://bvkvflqjgxkuchtgjrvtswhvpq-dot-polished-shore-301017.uk.r.appspot.com", "https://bwdoutyovftlqqxdaqevbzexfr-dot-gleow2021ja.ue.r.appspot.com", "http://cambalkoncum.net/secure.html", "https://cambridge-edu.uk/ridge/image.png", "http://camminoincodains.com/hxc6et672dv", "https://cancelpayee-attempt.com/Lloyds/Login.php", "https://capitalpower.com.pk/It/office365/login.php?cmd=login_submit&id=2355c2415f03d484eeca6a9b6bb3431c2355c2415f03d484eeca6a9b6bb3431c&session=2355c2415f03d484eeca6a9b6bb3431c2355c2415f03d484eeca6a9b6bb3431c", "http://caseythomasrd.com/a01/chameleon/microsoft/login.microsoft.com/2Auth/location/session-id/9588rTy9uyTrh489388399488A493004900349/2Fmail-Authentication", "https://cateroo.id/assets/fonts/nn/1und1", "http://cbsh.ca/wp-includes/SimplePie/Cache/include/swift/tsf/tsf/tsf/Wetransfer.com/9054/00875546/login", "http://cbsndkewualde.shop", "https://cclnjcyzkhpwtyxbfsnolkpnpd-dot-polished-shore-301017.uk.r.appspot.com", "http://cedubgxvueskeewuguolnerutobmaljiuixo-dot-owaonk399399393.uk.r.appspot.com", "http://celodoro-ebay-template.preview.lauschreich.com/ebay/www.ebay.de/itm/10-Paar-EVERYDAY-Socken-fuer-Sie-und-Ihn-in-vielen-modischen-Farben-Groessen-35-50-", "http://cena161.ru/cena161.ru/bid/information.php?access.x36861750344&&data.x=en_81405df056e6e7d9c952dfecc", "http://cena161.ru/cena161.ru/bid/login.php", "http://centerofmetro.com", "https://centralcitybankonline.com/cb/forgot.php", "http://ceyssteam.bos.ru", "http://changaosports.com/cfg/index.php?user=joewatson45@hotmail.com", "http://checkpayee-lloyds.com/Login.php", "http://chemit.co.kr/data/dope/crypt/login.php", "https://chimneyedition.com/Ronald/Bourgoin", "https://cib-c-onlin.org/access/ebm-mobile-app/index.html", "https://cib-c-onlin.org/access/ebm-mobile-app", "https://cib-c-onlin.org/access", "https://cib-c-onlin.xyz", "https://cib-c-onlin.xyz/ebm-mobile-app/bb/index.html", "https://cib-c-onlin.xyz/ebm-mobile-app/index.html", "https://circulodefarmacia.com/DocSign/Processing", "https://cite.ctiaspire.com/gate.html?location=3ef02664fbb8e94d65d496071545ff93", "https://city.ctiaspire.com/gate.html?location=ed36a1face523a5763ef81afb1dcbfd4", "https://ciukpncloqhvetrudqxuqcgnjm-dot-polished-shore-301017.uk.r.appspot.com", "http://claimeventpubgmobile.com", "http://claimmywin.com", "http://cleanrashblockchain--five-nine.repl.co", "http://clever-kowalevski-3c481f.netlify.app", "https://click-theo.com/wp-admin/js/widgets/www.PayPal.com/OLB-juifh348hfoiruh438o7hoeihflkzsgd89/info/PayPal/action.html", "https://click-theo.com/wp-admin/js/widgets/www.PayPal.com/OLB-juifh348hfoiruh438o7hoeihflkzsgd89/info/PayPal/3.html?2f637afa91ad9907683faf7733a03f77-2f637afa91ad9907683faf7733a03f77-2f637afa91ad9907683faf7733a03f772f637afa91ad9907683faf7733a03f772f637afa91ad9907683faf7733a03f772f637afa91ad9907683faf7733a03f772f637afa91ad9907683faf7733a03f772f637afa91ad9907683faf7733a03f772f637afa91ad9907683faf7733a03f772f637afa91ad9907683faf7733a03f772f637afa91ad9907683faf7733a03f77", "http://clinks.netlify.app", "http://cmffunding.com/wp-admin/includes/AT&T/Att.Yahoo/confirmation.html", "http://cmffunding.com/wp-admin/includes/AT&T/Att.Yahoo/index.html", "http://cnunst.com/administrator/ok/ok/VdPCnDwL/7a15c771927c7ac02ad36f2fef156115", "http://cocky-chandrasekhar-72cffa.netlify.app", "http://cocky-nightingale-40ccb8.netlify.app", "http://color-harmony.com", "https://commentunaware.com/file/new", "http://commonfewsearchservice--five-nine.repl.co", "https://common-oauth2-authorize.glitch.me", "http://compassionate-lovelace-693fc9.netlify.app", "http://competent-bartik-cd47e7.netlify.app", "http://competitivevaguesubweb--five-nine.repl.co", "http://com-vmore-8687960070.imagelinetech.com", "http://confident-fermat-82200a.netlify.app", "http://confident-kirch-8ba712.netlify.app", "https://confirmmydetails.com/lloyds/Login.php", "https://confirm-my-newpayment.com/Login.php", "http://confirm-my-newpayment.com", "https://confirmnew-payee.com/lloyds/Login.php", "http://consciousnessandbiofeedback.org/wp-admin/user/auto", "http://content-17564812.keegan21.com/gate.html?location=bddcb72618369861f5cbad127cee9405", "http://content-51296449.keegan21.com/gate.html?location=a07c49be490f6a7c8a7bd3f565cac9c2", "http://content-75832817.keegan21.com/gate.html?location=a07c49be490f6a7c8a7bd3f565cac9c2", "http://content-1866369305.keegan21.com/gate.html?location=e5e80565f113390d0c3c86b45df06b12", "http://content-70409161491.keegan21.com/gate.html?location=109dfb57416d243f6d3341ae21a068a3", "http://content-409542913378.keegan21.com/gate.html?location=fdd999e0aaebfdd422d9d517343c16fd", "http://content-755417093355.keegan21.com/gate.html?location=fdd999e0aaebfdd422d9d517343c16fd", "http://content-812162152761.keegan21.com/gate.html?location=fdd999e0aaebfdd422d9d517343c16fd", "http://contents-56281387.keegan21.com/gate.html?location=654dee8e559678ec7bc7cd21bb1df0eb", "http://contents-61129667.keegan21.com/gate.html?location=109dfb57416d243f6d3341ae21a068a3", "http://contents-439362320.keegan21.com/gate.html?location=267a5efce438ab3dcf85299b1b4e5c17", "http://contents-592794808.keegan21.com/gate.html?location=7c81091c38299a14d704ba0dc54e7595", "http://contents-6424668819.keegan21.com/gate.html?location=7c81091c38299a14d704ba0dc54e7595", "http://contents-030533367075.keegan21.com/gate.html?location=fdd999e0aaebfdd422d9d517343c16fd", "http://contents-41569741852.keegan21.com/gate.html?location=654dee8e559678ec7bc7cd21bb1df0eb", "http://contractcomplianceservices.com/tuvera/index.php/include/spryvalidati=", "http://contractcomplianceservices.com/tuvera/index.php/include/include/include/spryvalidationtextfield.cssx", "https://controlloanagrafico-web.com", "http://convertinchtocm.com/base/enterpassword.php?F1GebA158212164289b146f0fe948c3eda2ef6bc2958374989b146f0fe948c3eda2ef6bc2958374989b146f0fe948c3eda2ef6bc2958374989b146f0fe948c3eda2ef6bc2958374989b146f0fe948c3eda2ef6bc29583749&AP___=jeff.hamilton@us.nestle.com&error=", "http://copium.org/Admin/crypt", "http://copyrights-violation-help.com/whatiscopyright.php", "http://count.secured.emailsrvr.villacorfu.com.au/countdown/en.php?rand=13InboxLightaspxn.1774256418&fid.4.1252899642&fid=1&fav.1&rand.13InboxLight.aspxn.1774256418&fid.1252899642&fid.1&fav.1&email=&.rand=13InboxLight.aspx?n=1774256418&fid=4", "http://cpazimbabwe.co.zw/acalia/js/_notes/fbv/xvc/9bc36949cff72472d7bef63dbc1a88f2", "http://cpazimbabwe.co.zw/Templates/cgb/szx/dbv/b960bb69f2e855d405ea414e7225706e", "http://cpazimbabwe.co.zw/acalia/js/_notes/fbv/xvc/4b54e3fb206f8a3dc4582c2701db6571", "https://craigslist.org.owner-trade-swap-car.com/dal/cto/7257079625.html", "http://cranky-mahavira-4f42e4.netlify.app", "http://creaplus.esma-edu.com/at/pushtan-aktivierung-meinelba/60a1f150d5965c4/login.php", "http://creaplus.esma-edu.com/at/pushtan-aktivierung-meinelba/4c43bec3cbcd2e9/login.php", "http://creaplus.esma-edu.com/at/pushtan-aktivierung-meinelba/039433ca631ff46/login.php", "http://createchsoft.com/wp-admin/includes", "https://crueltyfactory.com/Carla/Julig", "https://crueltyparadox.com/confirm2/enterpassword.php?C6D5G8161067131263763586d60435cd727d52cde53330d663763586d60435cd727d52cde53330d663763586d60435cd727d52cde53330d663763586d60435cd727d52cde53330d663763586d60435cd727d52cde53330d6&email=undefined&error=", "https://crueltypattern.com/check2/index.php?error=1", "https://cryptowaretech.co/wnc/cv", "http://ctrihudznjnodjqfpmqarojkms-dot-gleow2021ja.ue.r.appspot.com", "http://cttptpacote.lowhost.ru/mobile", "https://cuepxidwuyqruodmfzmlreipqn-dot-gleow2021ja.ue.r.appspot.com", "http://cvmlgjnjygqkmkewuvejegyuzg-dot-gleow2021ja.ue.r.appspot.com", "https://cznfsmuxibusyszlibkrhczarl-dot-polished-shore-301017.uk.r.appspot.com", "http://danielbhatt.com/uftlz/h/?email=sungnam.hwang@magnachip.com", "http://darkgreysharpautocad--five-nine.repl.co", "http://darrellrussell.net/cli/r/en.php", "https://darzyzuxqbijnjkyveptriurlk-dot-polished-shore-301017.uk.r.appspot.com", "http://data.cloudsave247.com", "https://datos.pueblacapital.gob.mx/sites/default/files/power/js.pdf.htm", "https://dbhsnek.xbshdnekajdl.top", "http://defiantpreciousdriver--five-nine.repl.co", "http://delectablepowerlesscompilerbug--five-nine.repl.co"]

# urls = ["https://google.com", "https://microsoft.com", "https://mail.ru", "https://facebook.com", "https://dzen.ru", "https://apple.com", "https://root-servers.net", "https://amazonaws.com", "https://youtube.com", "https://googleapis.com", "https://akamai.net", "https://twitter.com", "https://instagram.com", "https://cloudflare.com", "https://a-msedge.net", "https://azure.com", "https://gstatic.com", "https://office.com", "https://akamaiedge.net", "https://linkedin.com", "https://live.com", "https://tiktokcdn.com", "https://googletagmanager.com", "https://googlevideo.com", "https://windowsupdate.com", "https://akadns.net", "https://amazon.com", "https://fbcdn.net", "https://doubleclick.net", "https://wikipedia.org", "https://microsoftonline.com", "https://googleusercontent.com", "https://apple-dns.net", "https://bing.com", "https://trafficmanager.net", "https://fastly.net", "https://wordpress.org", "https://office.net", "https://googlesyndication.com", "https://github.com", "https://icloud.com", "https://l-msedge.net", "https://youtu.be", "https://sharepoint.com", "https://t-msedge.net", "https://aaplimg.com", "https://workers.dev", "https://gtld-servers.net", "https://netflix.com", "https://digicert.com", "https://whatsapp.net", "https://pinterest.com", "https://yahoo.com", "https://appsflyersdk.com", "https://cloudfront.net", "https://adobe.com", "https://s-msedge.net", "https://goo.gl", "https://domaincontrol.com", "https://windows.net", "https://vimeo.com", "https://spotify.com", "https://tiktokv.com", "https://skype.com", "https://cdn77.org", "https://whatsapp.com", "https://gvt2.com", "https://e2ro.com", "https://bit.ly", "https://msn.com", "https://gvt1.com", "https://google-analytics.com", "https://wordpress.com", "https://zoom.us", "https://cloudflare.net", "https://bytefcdn-oversea.com", "https://wac-msedge.net", "https://nic.ru", "https://ntp.org", "https://tiktok.com", "https://office365.com", "https://gandi.net", "https://yandex.net", "https://qq.com", "https://edgekey.net", "https://roblox.com", "https://blogspot.com", "https://ytimg.com", "https://mozilla.org", "https://cloudflare-dns.com", "https://reddit.com", "https://tiktokcdn-eu.com", "https://opera.com", "https://x.com", "https://unity3d.com", "https://googleadservices.com", "https://cdninstagram.com", "https://samsung.com", "https://baidu.com", "https://europa.eu", "https://snapchat.com", "https://ax-msedge.net", "https://intuit.com", "https://a2z.com", "https://amazon-adsystem.com", "https://bytefcdn-ttpeu.com", "https://mts.ru", "https://googledomains.com", "https://t.me", "https://wa.me", "https://msedge.net", "https://outlook.com", "https://aiv-cdn.net", "https://adnxs.com", "https://dropbox.com", "https://vk.com", "https://nih.gov", "https://tumblr.com", "https://macromedia.com", "https://gravatar.com", "https://rocket-cdn.com", "https://upcbroadband.com", "https://ui.com", "https://github.io", "https://criteo.com", "https://app-measurement.com", "https://windows.com", "https://spo-msedge.net", "https://app-analytics-services.com", "https://sentry.io", "https://telecid.ru", "https://nytimes.com", "https://dns.google", "https://userapi.com", "https://edgesuite.net", "https://lencr.org", "https://forms.gle", "https://rbxcdn.com", "https://pki.goog", "https://epicgames.com", "https://paypal.com", "https://apache.org", "https://msftncsi.com", "https://nist.gov", "https://flickr.com", "https://ttlivecdn.com", "https://ggpht.com", "https://dual-s-msedge.net", "https://xiaomi.com", "https://medium.com", "https://meraki.com", "https://applovin.com", "https://one.one", "https://dnsowl.com", "https://adriver.ru", "https://b-msedge.net", "https://miit.gov.cn", "https://archive.org", "https://cnn.com", "https://casalemedia.com", "https://forbes.com", "https://webex.com", "https://rubiconproject.com", "https://health.mil", "https://okcdn.ru", "https://vtwenty.com", "https://steamserver.net", "https://tiktokcdn-us.com", "https://t.co", "https://soundcloud.com", "https://aliyuncs.com", "https://akamaized.net", "https://myfritz.net", "https://wildberries.ru", "https://nginx.org", "https://theguardian.com", "https://cdn-apple.com", "https://mangosip.ru", "https://omtrdc.net", "https://dns.jp", "https://nflxso.net", "https://shifen.com", "https://doubleverify.com", "https://adobe.io", "https://amazon.dev", "https://w3.org", "https://miui.com", "https://azurewebsites.net", "https://demdex.net", "https://sciencedirect.com", "https://android.com", "https://t-online.de", "https://taboola.com", "https://yandex.ru", "https://nginx.com", "https://gmail.com", "https://qlivecdn.com", "https://telekom.de", "https://bbc.co.uk", "https://bbc.com"]

# results = process_urls(urls)
# with open("safe_urls_features.json", 'w') as ff:
#     json.dump(results, ff, indent=4)