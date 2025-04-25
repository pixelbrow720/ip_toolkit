#!/usr/bin/env python3
"""
Web Crawler Script - Similar to OWASP ZAP Spider and Ajax Spider
This script provides functionality to crawl websites using both traditional
crawling methods and JavaScript-enabled crawling for dynamic content.
"""

import argparse
import re
import time
import urllib.parse
from collections import deque
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class WebCrawler:
    """Web crawler with both traditional and JavaScript-enabled crawling capabilities."""

    def __init__(self, start_url, max_depth=3, respect_robots=True, 
                 delay=1, timeout=30, headers=None, cookies=None):
        """
        Initialize the web crawler.
        
        Args:
            start_url (str): The starting URL for the crawler
            max_depth (int): Maximum depth to crawl
            respect_robots (bool): Whether to respect robots.txt
            delay (int): Delay between requests in seconds
            timeout (int): Request timeout in seconds
            headers (dict): Custom headers for requests
            cookies (dict): Cookies to use for requests
        """
        self.start_url = start_url
        self.base_url = self._get_base_url(start_url)
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.delay = delay
        self.timeout = timeout
        
        # Default headers to mimic a browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if headers:
            self.headers.update(headers)
            
        self.cookies = cookies or {}
        self.visited_urls = set()
        self.found_urls = set()
        self.forms = []
        self.ajax_urls = []
        
        # Initialize robots.txt parser if needed
        self.robots_parser = None
        if self.respect_robots:
            self.robots_parser = RobotFileParser()
            self.robots_parser.set_url(urllib.parse.urljoin(self.base_url, '/robots.txt'))
            try:
                self.robots_parser.read()
            except Exception as e:
                print(f"Error reading robots.txt: {e}")
                
        # Initialize Selenium for Ajax crawling
        self.driver = None
    
    def _get_base_url(self, url):
        """Extract the base URL (scheme + netloc) from a URL."""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _is_valid_url(self, url):
        """Check if a URL is valid and should be crawled."""
        # Skip non-HTTP(S) URLs
        if not url.startswith(('http://', 'https://')):
            return False
            
        # Skip URLs outside the base domain
        if not url.startswith(self.base_url):
            return False
            
        # Skip already visited URLs
        if url in self.visited_urls:
            return False
            
        # Check robots.txt
        if self.respect_robots and self.robots_parser:
            if not self.robots_parser.can_fetch('*', url):
                print(f"Skipping {url} (disallowed by robots.txt)")
                return False
                
        return True
    
    def _normalize_url(self, url, base_url):
        """Normalize a URL (handle relative URLs, fragments, etc.)."""
        # Remove fragments
        url = url.split('#')[0]
        if not url:
            return None
            
        # Handle relative URLs
        if not url.startswith(('http://', 'https://')):
            url = urllib.parse.urljoin(base_url, url)
            
        return url
    
    def _extract_links(self, soup, base_url):
        """Extract links from a BeautifulSoup object."""
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href')
            normalized_url = self._normalize_url(href, base_url)
            if normalized_url:
                links.append(normalized_url)
        return links
    
    def _extract_forms(self, soup, url):
        """Extract forms from a BeautifulSoup object."""
        forms_data = []
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Normalize form action URL
            if form_data['action']:
                form_data['action'] = self._normalize_url(form_data['action'], url)
            else:
                form_data['action'] = url
                
            # Extract form inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text') if input_tag.name == 'input' else input_tag.name,
                    'value': input_tag.get('value', '')
                }
                if input_data['name']:  # Only include inputs with names
                    form_data['inputs'].append(input_data)
                    
            forms_data.append(form_data)
        return forms_data
    
    def _extract_ajax_endpoints(self, page_source):
        """Extract potential AJAX endpoints from JavaScript code."""
        # Look for URLs in JavaScript
        url_pattern = r'(https?://[^\s\'"\)\}]+)'
        ajax_urls = re.findall(url_pattern, page_source)
        
        # Look for API endpoints
        api_pattern = r'[\'"](/api/[^\s\'"\)\}]+)[\'"]'
        api_endpoints = re.findall(api_pattern, page_source)
        
        # Normalize API endpoints
        for endpoint in api_endpoints:
            ajax_urls.append(urllib.parse.urljoin(self.base_url, endpoint))
            
        return list(set(ajax_urls))  # Remove duplicates
    
    def _init_selenium(self):
        """Initialize Selenium WebDriver for JavaScript-enabled crawling."""
        if self.driver is not None:
            return
            
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument(f'user-agent={self.headers["User-Agent"]}')
        
        try:
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(self.timeout)
        except Exception as e:
            print(f"Error initializing Selenium: {e}")
            print("Continuing with traditional crawling only.")
    
    def _close_selenium(self):
        """Close the Selenium WebDriver."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
    
    def traditional_crawl(self, url, depth=0):
        """
        Perform traditional crawling using requests and BeautifulSoup.
        
        Args:
            url (str): URL to crawl
            depth (int): Current crawl depth
        """
        if depth > self.max_depth or not self._is_valid_url(url):
            return
            
        print(f"Crawling: {url} (depth: {depth})")
        self.visited_urls.add(url)
        
        try:
            # Add delay to be respectful
            time.sleep(self.delay)
            
            # Make the request
            response = requests.get(
                url, 
                headers=self.headers, 
                cookies=self.cookies,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            # Parse the response
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            links = self._extract_links(soup, url)
            for link in links:
                self.found_urls.add(link)
            
            # Extract forms
            forms = self._extract_forms(soup, url)
            self.forms.extend(forms)
            
            # Extract potential AJAX endpoints
            ajax_endpoints = self._extract_ajax_endpoints(response.text)
            self.ajax_urls.extend(ajax_endpoints)
            
            # Continue crawling
            for link in links:
                if link not in self.visited_urls:
                    self.traditional_crawl(link, depth + 1)
                    
        except requests.exceptions.RequestException as e:
            print(f"Error crawling {url}: {e}")
    
    def ajax_crawl(self, url):
        """
        Perform JavaScript-enabled crawling using Selenium.
        
        Args:
            url (str): URL to crawl with JavaScript enabled
        """
        if not self._is_valid_url(url) or not self.driver:
            return
            
        print(f"AJAX Crawling: {url}")
        self.visited_urls.add(url)
        
        try:
            # Add delay to be respectful
            time.sleep(self.delay)
            
            # Load the page with Selenium
            self.driver.get(url)
            
            # Wait for JavaScript to execute
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Additional wait for dynamic content
            time.sleep(2)
            
            # Get the page source after JavaScript execution
            page_source = self.driver.page_source
            
            # Parse with BeautifulSoup
            soup = BeautifulSoup(page_source, 'html.parser')
            
            # Extract links
            links = self._extract_links(soup, url)
            for link in links:
                self.found_urls.add(link)
            
            # Extract forms
            forms = self._extract_forms(soup, url)
            self.forms.extend(forms)
            
            # Extract potential AJAX endpoints
            ajax_endpoints = self._extract_ajax_endpoints(page_source)
            self.ajax_urls.extend(ajax_endpoints)
            
            # Look for dynamically loaded content
            try:
                # Find all clickable elements
                clickable_elements = self.driver.find_elements(By.CSS_SELECTOR, 
                                                              'a, button, [role="button"], [onclick]')
                
                for element in clickable_elements[:10]:  # Limit to first 10 to avoid endless clicking
                    try:
                        # Try to click the element
                        element.click()
                        time.sleep(1)  # Wait for any content to load
                        
                        # Check if new content appeared
                        new_page_source = self.driver.page_source
                        if new_page_source != page_source:
                            # Extract links from the new content
                            new_soup = BeautifulSoup(new_page_source, 'html.parser')
                            new_links = self._extract_links(new_soup, url)
                            for link in new_links:
                                self.found_urls.add(link)
                        
                        # Go back to original state
                        self.driver.get(url)
                        WebDriverWait(self.driver, 10).until(
                            EC.presence_of_element_located((By.TAG_NAME, "body"))
                        )
                        time.sleep(1)
                        
                    except Exception:
                        # Ignore errors from clicking elements
                        continue
                        
            except Exception as e:
                print(f"Error exploring dynamic elements: {e}")
                
        except Exception as e:
            print(f"Error AJAX crawling {url}: {e}")
    
    def crawl(self):
        """Start the crawling process."""
        print(f"Starting crawl from {self.start_url}")
        
        # Traditional crawling
        self.traditional_crawl(self.start_url)
        
        # AJAX crawling for a subset of discovered URLs
        try:
            self._init_selenium()
            if self.driver:
                # Select a subset of URLs for AJAX crawling
                ajax_candidates = list(self.found_urls - self.visited_urls)[:10]
                for url in ajax_candidates:
                    self.ajax_crawl(url)
        finally:
            self._close_selenium()
            
        # Print results
        self._print_results()
    
    def _print_results(self):
        """Print crawling results."""
        print("\n=== Crawling Results ===")
        print(f"Total URLs found: {len(self.found_urls)}")
        print(f"URLs visited: {len(self.visited_urls)}")
        print(f"Forms discovered: {len(self.forms)}")
        print(f"Potential AJAX endpoints: {len(set(self.ajax_urls))}")
        
        print("\nTop 10 discovered URLs:")
        for url in list(self.found_urls)[:10]:
            print(f"  - {url}")
            
        print("\nForms discovered:")
        for i, form in enumerate(self.forms[:5]):  # Show first 5 forms
            print(f"  Form {i+1}: {form['method']} {form['action']}")
            print(f"    Inputs: {', '.join([inp['name'] for inp in form['inputs']])}")
            
        print("\nSample AJAX endpoints:")
        for url in list(set(self.ajax_urls))[:5]:  # Show first 5 unique AJAX endpoints
            print(f"  - {url}")


def main():
    """Parse command line arguments and start the crawler."""
    parser = argparse.ArgumentParser(description='Web Crawler (Spider and Ajax Spider)')
    parser.add_argument('url', help='Starting URL for the crawler')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth')
    parser.add_argument('--no-robots', action='store_true', help='Ignore robots.txt')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    
    args = parser.parse_args()
    
    crawler = WebCrawler(
        args.url,
        max_depth=args.depth,
        respect_robots=not args.no_robots,
        delay=args.delay,
        timeout=args.timeout
    )
    
    crawler.crawl()


if __name__ == "__main__":
    main()