import sys
import platform
from scanner import get_operating_system_by_ttl, scan_network

def test_os_ttl_logic():
    print("[*] Testing TTL OS finger-printing logic...")
    assert get_operating_system_by_ttl(64) == "Linux/Unix", "TTL 64 should register as Linux!"
    assert get_operating_system_by_ttl(128) == "Windows", "TTL 128 should register as Windows!"
    print("[+] TTL Fingerprinting test passed successfully.")

def test_scan_execution_syntax():
    print("[*] Testing local loopback interface parsing...")
    # Scan localhost to verify the parsing framework operates smoothly without network side-effects
    results = scan_network("127.0.0.1")
    assert isinstance(results, list), "Scanner output matrix must return a valid list array!"
    print("[+] Framework execution syntax test passed successfully.")

if __name__ == "__main__":
    print(f"=== Beginning Scanner Verification suite on {platform.system()} ===")
    try:
        test_os_ttl_logic()
        test_scan_execution_syntax()
        print("\n[SUCCESS] All code execution verification checks passed perfectly on this host.")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n[FAILURE] Code assertions verification failed: {e}")
        sys.exit(1)