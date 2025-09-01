import requests
import time

NVD_API_KEY = ""

def fetch_cvss_from_nvd(cve_id):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"apiKey": NVD_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return "Unknown"

        metrics = vulnerabilities[0]["cve"].get("metrics", {})

        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        else:
            return "Unknown"

        return str(score)

    except Exception as e:
        print(f"[ERROR] Failed to fetch CVSS for {cve_id}: {e}")
        return "Unknown"
    finally:
        time.sleep(1.5)  # To avoid rate limiting

cve = "CVE-2015-4000"
print("CVSS Score:", fetch_cvss_from_nvd(cve))
