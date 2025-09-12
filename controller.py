from urllib.parse import urlsplit, urlunsplit, quote
import tldextract
import time
import requests
import model  # assuming your existing model module

class Controller:
    def __init__(self):
        self.BASE_SCORE = 50  # default trust score of URL out of 100
        self.model = model

    def safe_url(self, url):
        """
        Safely encode URL without breaking query strings or path.
        """
        parts = urlsplit(url)
        path = quote(parts.path)  # encode path
        query = quote(parts.query, safe="=&")  # encode query but keep = & symbols
        return urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))

    def check_url_reachability(self, url):
        try:
            url = self.safe_url(url)  # safely encode URL

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36'
            }

            # Allow redirects, 15-second timeout, SSL verification
            response = requests.get(url, timeout=15, headers=headers, allow_redirects=True, verify=True)

            if 200 <= response.status_code < 400:
                return True, response.status_code
            else:
                return False, f"HTTP Error {response.status_code}"

        except requests.exceptions.SSLError as e:
            return False, f"SSL Error: {e}"
        except requests.exceptions.ConnectTimeout as e:
            return False, f"Timeout Error: {e}"
        except requests.exceptions.ConnectionError as e:
            return False, f"Connection Error: {e}"
        except requests.exceptions.TooManyRedirects as e:
            return False, f"Too Many Redirects: {e}"
        except requests.exceptions.RequestException as e:
            return False, f"Request Exception: {e}"
        except Exception as e:
            return False, f"Unknown Error: {e}"

    def main(self, url):
        try:
            print(time.time(), "entry")

            # Ensure protocol is included
            url = self.model.include_protocol(url)
            print(time.time(), "include_protocol")

            # Check if the URL is reachable
            is_reachable, status = self.check_url_reachability(url)
            if not is_reachable:
                return {
                    'status': 'ERROR',
                    'url': url,
                    'trust_score': 60,
                    'reason': f'URL is not reachable: {status}',
                    'response_status': status,
                    'age': None,
                    'rank': None,
                    'is_url_shortened': None,
                    'hsts_support': None,
                    'ssl': None,
                    'whois': None,
                }

            # Validate URL
            url_validation = self.model.validate_url(url)
            print(time.time(), "validate_url")

            # Default response data
            domain_info = tldextract.extract(url)
            domain = domain_info.domain + '.' + domain_info.suffix
            response = {'status': 'SUCCESS', 'url': url}
            trust_score = self.BASE_SCORE

            # Phishtank check
            phishtank_response = self.model.phishtank_search(url)
            print(time.time(), "phishtank_search")
            if phishtank_response:
                response['msg'] = "This is a verified phishing link."

            # Website status
            response['response_status'] = url_validation

            # Domain rank
            domain_rank = self.model.get_domain_rank(domain)
            print(time.time(), "get_domain_rank")
            trust_score = self.model.calculate_trust_score(trust_score, 'domain_rank', domain_rank)
            response['rank'] = domain_rank if domain_rank else '10,00,000+'

            # Domain age & WHOIS
            # Domain age & WHOIS
            whois_data = self.model.whois_data(domain)
            print(time.time(), "whois_data")

            whois_age = whois_data.get('age', 0)  # default to 0 if missing

            # Safely handle age for response display
            if isinstance(whois_age, (int, float)):
                response['age'] = f"{round(whois_age, 1)} year(s)"
            elif isinstance(whois_age, str) and whois_age.lower() == 'not given':
                response['age'] = 'Not Given'
            else:
                response['age'] = 'Unknown'

            # Ensure a numeric value is used for trust score calculation
            trust_score = self.model.calculate_trust_score(
                trust_score,
                'domain_age',
                whois_age if isinstance(whois_age, (int, float)) else 0
            )

            # Store the full WHOIS data
            response['whois'] = whois_data.get('data', 'Unavailable')

            # URL shortening
            is_url_shortened = self.model.is_url_shortened(url)
            print(time.time(), "is_url_shortened")
            trust_score = self.model.calculate_trust_score(trust_score, 'is_url_shortened', is_url_shortened)
            response['is_url_shortened'] = is_url_shortened

            # HSTS support
            hsts_support = self.model.hsts_support(url)
            print(time.time(), "hsts_support")
            trust_score = self.model.calculate_trust_score(trust_score, 'hsts_support', hsts_support)
            response['hsts_support'] = hsts_support

            # IP presence in URL
            ip_present = self.model.ip_present(url)
            print(time.time(), "ip_present")
            trust_score = self.model.calculate_trust_score(trust_score, 'ip_present', ip_present)
            response['ip_present'] = ip_present

            # URL redirects
            url_redirects = self.model.url_redirects(url)
            print(time.time(), "url_redirects")
            trust_score = self.model.calculate_trust_score(trust_score, 'url_redirects', url_redirects)
            response['url_redirects'] = url_redirects

            # URL length
            too_long_url = self.model.too_long_url(url)
            print(time.time(), "too_long_url")
            trust_score = self.model.calculate_trust_score(trust_score, 'too_long_url', too_long_url)
            response['too_long_url'] = too_long_url

            # URL depth
            too_deep_url = self.model.too_deep_url(url)
            print(time.time(), "too_deep_url")
            trust_score = self.model.calculate_trust_score(trust_score, 'too_deep_url', too_deep_url)
            response['too_deep_url'] = too_deep_url

            # IP of domain
            ip = self.model.get_ip(domain)
            print(time.time(), "get_ip")
            response['ip'] = 'Unavailable' if ip == 0 else ip

            # SSL certificate details
            ssl = self.model.get_certificate_details(domain)
            print(time.time(), "get_certificate_details")
            response['ssl'] = ssl

            # Final trust score
            trust_score = int(max(min(trust_score, 100), 0))
            response['trust_score'] = trust_score

            return response

        except Exception as e:
            print(f"Error: {e}")
            response = {
                'status': 'ERROR',
                'url': url,
                'msg': "Some error occurred, please check the URL.",
                'emsg': str(e)
            }
            return response
