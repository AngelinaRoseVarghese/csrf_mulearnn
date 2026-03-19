import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys

class CSRFCrawler:
    def __init__(self, start_url, session_cookies=None):
        self.start_url = start_url
        self.session = requests.Session()
        if session_cookies:
            self.session.cookies.update(session_cookies)
        self.visited_urls = set()
        self.csrf_field_indicators = [
            'csrf', 'csrf_token', 'csrfmiddlewaretoken', '__csrf',
            'authenticity_token', '_token', 'xsrf-token', 'csrf-token'
        ]

    def crawl(self, url=None):
        if url is None:
            url = self.start_url

        if url in self.visited_urls:
            return
        print(f"[*] Crawling: {url}")
        self.visited_urls.add(url)

        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                print(f"[!] Received status code {response.status_code} for {url}")
                return
        except requests.RequestException as e:
            print(f"[!] Error fetching {url}: {e}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        self.analyze_forms(soup, url)
        self.find_links(soup, url)

    def analyze_forms(self, soup, page_url):
        forms = soup.find_all('form')
        if not forms:
            return

        print(f"\n[--- Analysing {len(forms)} form(s) on {page_url} ---]")
        for i, form in enumerate(forms):
            form_action = form.get('action')
            form_method = form.get('method', 'get').upper()
            form_details = {
                'action': urljoin(page_url, form_action) if form_action else page_url,
                'method': form_method,
                'inputs': []
            }

            inputs = form.find_all('input')
            has_csrf_token = False
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', '').lower()
                if input_name:
                    form_details['inputs'].append({'name': input_name, 'type': input_type})
                    if any(indicator in input_name.lower() for indicator in self.csrf_field_indicators):
                        has_csrf_token = True

            if form_method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                if not has_csrf_token:
                    vulnerability_score = "HIGH"
                    reason = "State-changing method without a detectable CSRF token field."
                else:
                    vulnerability_score = "LOW"
                    reason = "Form has a field that appears to be a CSRF token."
                print(f"\n  Form #{i+1} -> {form_details['method']} to {form_details['action']}")
                print(f"  [VULNERABILITY SCORE: {vulnerability_score}] - {reason}")
            else:
                print(f"\n  Form #{i+1} (GET) to {form_details['action']} - not typically vulnerable for state changes.")

    def find_links(self, soup, current_url):
        parsed_current = urlparse(current_url)
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = urljoin(current_url, href)
            parsed_link = urlparse(full_url)

            if (parsed_link.netloc == parsed_current.netloc and
                    parsed_link.scheme in ['http', 'https'] and
                    full_url not in self.visited_urls and
                    '#' not in full_url):
                self.crawl(full_url)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python csrf_crawler.py <start_url> [--cookie 'name=value; name2=value2']")
        sys.exit(1)

    target_url = sys.argv[1]
    cookies = {}
    if '--cookie' in sys.argv:
        cookie_index = sys.argv.index('--cookie') + 1
        if cookie_index < len(sys.argv):
            cookie_str = sys.argv[cookie_index]
            for item in cookie_str.split(';'):
                if '=' in item:
                    name, value = item.strip().split('=', 1)
                    cookies[name] = value

    crawler = CSRFCrawler(target_url, session_cookies=cookies if cookies else None)
    print(f"[+] Starting CSRF crawl on {target_url}")
    crawler.crawl()
