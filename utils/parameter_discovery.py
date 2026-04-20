import requests
from urllib.parse import urlparse, parse_qs
import sys


def discover_parameters(url):
    """Discover parameters in a URL by analyzing query string and common patterns"""
    parsed = urlparse(url)
    
    # Get existing parameters from query string
    params = list(parse_qs(parsed.query).keys())
    
    # Also check for common parameter names in the path
    common_params = ['id', 'user', 'page', 'search', 'q', 'query', 'file', 'path', 'url', 'redirect', 
                    'callback', 'return', 'next', 'target', 'dest', 'destination', 'uri', 'url', 'link',
                    'cat', 'category', 'item', 'product', 'type', 'sort', 'order', 'limit', 'offset',
                    'email', 'username', 'password', 'login', 'auth', 'token', 'key', 'secret',
                    'data', 'value', 'input', 'content', 'message', 'text', 'comment', 'name',
                    'lang', 'language', 'locale', 'country', 'region', 'city', 'state', 'zip',
                    'date', 'time', 'year', 'month', 'day', 'hour', 'minute', 'second',
                    'format', 'output', 'view', 'action', 'method', 'type', 'mode', 'state']
    
    # Check if common params appear in the path
    path_parts = parsed.path.lower().split('/')
    for param in common_params:
        if param in path_parts:
            if param not in params:
                params.append(param)
    
    return params


def discover_parameters_from_file(file_path, output_file):
    """Discover parameters from a file of URLs"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return
    
    url_params = {}
    
    for url in urls:
        params = discover_parameters(url)
        if params:
            url_params[url] = params
    
    # Write results to output file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("URL,Parameters\n")
        for url, params in url_params.items():
            f.write(f"{url},{','.join(params)}\n")
    
    print(f"Parameter discovery complete. Found parameters for {len(url_params)} URLs.")
    print(f"Results saved to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parameter_discovery.py <input_file> <output_file>")
        print("Example: python parameter_discovery.py urls.txt params.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    discover_parameters_from_file(input_file, output_file)
