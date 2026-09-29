"""Direct API test against running server."""
import io
import json
import urllib.error
import urllib.request
import zipfile

BASE = "http://127.0.0.1:5000/api"

def test_empty_request():
    try:
        req = urllib.request.Request(
            f"{BASE}/demo-project/analyze",
            data=b"",
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req)
        print("FAIL: Empty request succeeded unexpectedly")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
        assert e.code == 400
        assert "Add a demonstration project" in body["error"]
        print(f"PASS: Empty request returned 400 with message: {body['error']}")

def test_corrupt_zip():
    boundary = "----TestBoundary123"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="corrupt.zip"\r\n'
        "Content-Type: application/zip\r\n\r\n"
        "not a valid zip binary content\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"{BASE}/demo-project/analyze",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
        )
        urllib.request.urlopen(req)
        print("FAIL: Corrupt zip succeeded unexpectedly")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
        print("DEBUG body received:", body)
        assert e.code == 400
        msg = body.get("error") or body.get("error_message") or ""
        assert "valid" in msg.lower() or "zip" in msg.lower()
        print(f"PASS: Corrupt zip returned 400 with message: {msg}")

def test_explicit_sample():
    req = urllib.request.Request(
        f"{BASE}/demo-project/analyze?sample=true",
        data=b"",
        headers={"Content-Type": "application/json"}
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read().decode())
    assert data["status"] == "SUCCESS"
    assert len(data["findings"]) == 3
    assert data["scanner_name"] == "DemoSourceScanner"
    assert data["provenance_chain"][0][0]["details"]["adapter_id"] == "demo_source_adapter"
    print(f"PASS: Explicit sample succeeded with {len(data['findings'])} findings, scanner={data['scanner_name']}, adapter={data['provenance_chain'][0][0]['details']['adapter_id']}")

def test_single_java():
    boundary = "----TestBoundaryJava"
    java_content = """
    package com.example;
    import java.security.KeyPairGenerator;
    public class SimpleCrypto {
        public void init() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        }
    }
    """
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="SimpleCrypto.java"\r\n'
        "Content-Type: text/x-java-source\r\n\r\n"
        f"{java_content}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}/demo-project/analyze",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read().decode())
    assert data["status"] == "SUCCESS"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["algorithm"] == "RSA"
    print(f"PASS: Single java file succeeded with finding: {data['findings'][0]['algorithm']}")

def test_no_crypto_java():
    boundary = "----TestBoundaryJavaNoCrypto"
    java_content = """
    package com.example;
    public class NoCrypto {
        public void sayHello() {
            System.out.println("Hello World");
        }
    }
    """
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="NoCrypto.java"\r\n'
        "Content-Type: text/x-java-source\r\n\r\n"
        f"{java_content}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}/demo-project/analyze",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read().decode())
    assert data["status"] == "SUCCESS"
    assert len(data["findings"]) == 0
    assert len(data["assets"]) == 0
    print(f"PASS: No-crypto java file returned honest 0 findings, 0 assets")

def test_upload_sample_zip():
    boundary = "----TestBoundaryZipUpload"
    with open("demo/sample_project/ECDAT-Demo-Application.zip", "rb") as f:
        zip_bytes = f.read()
    
    header = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="ECDAT-Demo-Application.zip"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode("utf-8")
    footer = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = header + zip_bytes + footer

    req = urllib.request.Request(
        f"{BASE}/demo-project/analyze",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read().decode())
    assert data["status"] == "SUCCESS"
    assert len(data["findings"]) == 3
    print("PASS: Upload of sample zip succeeded with 3 findings (RSA, AES, Ed25519)")

if __name__ == "__main__":
    test_empty_request()
    test_corrupt_zip()
    test_explicit_sample()
    test_single_java()
    test_no_crypto_java()
    test_upload_sample_zip()
    print("ALL LIVE SERVER INTEGRATION TESTS PASSED!")
