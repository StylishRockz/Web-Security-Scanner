from flask import Flask, render_template, request
import asyncio
import aiohttp
import ssl
import socket
from urllib.parse import urlparse
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)

async def scan_headers(session, url):
    try:
        async with session.get(url, allow_redirects=True, timeout=10) as response:
            headers = response.headers
            issues = []

            security_headers = [
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'X-Content-Type-Options',
                'Referrer-Policy'
            ]

            for header in security_headers:
                if header not in headers:
                    issues.append(f"{header} header is missing")

            return issues
    except asyncio.TimeoutError:
        return ["Timeout while checking headers"]
    except Exception as e:
        logging.error(f"Error checking headers: {str(e)}")
        return [f"Error checking headers: {str(e)}"]

async def scan_ssl(hostname):
    try:
        context = ssl.create_default_context()
        conn = asyncio.open_connection(hostname, 443, ssl=context)
        _, writer = await asyncio.wait_for(conn, timeout=10)
        writer.close()
        await writer.wait_closed()
        return []
    except ssl.SSLError as e:
        return [f"SSL/TLS configuration issue: {str(e)}"]
    except asyncio.TimeoutError:
        return ["Timeout while checking SSL"]
    except Exception as e:
        logging.error(f"Error checking SSL: {str(e)}")
        return [f"Error checking SSL: {str(e)}"]

async def scan_ports(hostname):
    common_ports = [80, 443, 22, 21, 25, 110, 143, 3306, 3389]
    tasks = [asyncio.open_connection(hostname, port) for port in common_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    open_ports = [port for port, result in zip(common_ports, results) if result is None]
    return [f"Open ports: {', '.join(map(str, open_ports))}"]

async def scan_wordpress(session, url):
    try:
        async with session.get(f"{url}/wp-login.php", allow_redirects=False, timeout=10) as response:
            text = await response.text()
            if response.status == 200 and "wordpress" in text.lower():
                return ["Website appears to be using WordPress. Ensure it's updated and properly secured."]
    except:
        pass
    return []

async def scan_server_info(session, url):
    try:
        async with session.get(url, allow_redirects=True, timeout=10) as response:
            server = response.headers.get('Server', '')
            if server:
                return [f"Server information disclosed: {server}"]
    except:
        pass
    return []

async def perform_scan(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc

    async with aiohttp.ClientSession() as session:
        tasks = [
            scan_headers(session, url),
            scan_ssl(hostname),
            scan_ports(hostname),
            scan_wordpress(session, url),
            scan_server_info(session, url)
        ]

        results = await asyncio.gather(*tasks)
        all_issues = []
        for result in results:
            all_issues.extend(result)

        return all_issues

loop = asyncio.get_event_loop()

@app.route('/', methods=['GET', 'POST'])
def scanner():
    if request.method == 'POST':
        url = request.form['url']
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            all_issues = loop.run_until_complete(perform_scan(url))
            return render_template('results.html', issues=all_issues, url=url)
        except Exception as e:
            logging.error(f"Error performing scan: {str(e)}")
            return render_template('results.html', issues=[f"Error: {str(e)}"], url=url)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
