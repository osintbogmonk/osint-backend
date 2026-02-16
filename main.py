from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import whois
import dns.resolver
import httpx
import re

app = FastAPI(title="OSINT Backend")

class AnalyzeRequest(BaseModel):
    type: str
    value: str

def extract_domain_from_email(email: str) -> str:
    m = re.search(r"@([^@]+)$", email)
    if not m:
        raise ValueError("Invalid email")
    return m.group(1).lower()

def safe_whois(domain: str):
    try:
        w = whois.whois(domain)
        # whois.whois returns an object; convert to dict for JSON serialisation
        return dict(w) if hasattr(w, "__dict__") else w
    except Exception as e:
        return {"error": str(e)}

def dns_lookup(domain: str):
    out = {}
    resolver = dns.resolver.Resolver()
    for rtype in ("A", "MX", "TXT"):
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5)
            out[rtype] = [r.to_text() for r in answers]
        except Exception as e:
            out[rtype] = {"error": str(e)}
    return out

async def http_check(domain: str):
    url = f"https://{domain}"
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        try:
            r = await client.get(url)
            title = None
            # try to extract <title> from body if present (simple)
            if r.text:
                m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()
            return {"status_code": r.status_code, "title": title, "final_url": str(r.url)}
        except Exception as e:
            return {"error": str(e)}

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    t = req.type.lower()
    val = req.value.strip()
    if t not in ("email", "domain"):
        raise HTTPException(status_code=400, detail="type must be 'email' or 'domain'")

    if t == "email":
        try:
            domain = extract_domain_from_email(val)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid email")
    else:
        domain = val.lower()

