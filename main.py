"""
SoraaAI Backend — FastAPI
API Key System + Claude & OpenAI Proxy
Deploy: Railway / Render / Fly.io
"""

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Literal
import httpx
import secrets
import string
import json
import os
import time
from datetime import datetime, timedelta

app = FastAPI(title="SoraaAI API", version="1.0.0")

# ─── CORS (izinkan semua origin untuk development, restrict di production) ───
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Ganti dengan domain kamu di production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── CONFIG (set via environment variables di Railway/Render) ───
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")   # Claude API key kamu
OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY", "")       # OpenAI API key kamu
ADMIN_SECRET      = os.getenv("ADMIN_SECRET", "soraaai-admin-super-secret-2024")

# ─── IN-MEMORY API KEY STORE ───
# Di production gunakan Redis atau database (Supabase, PlanetScale, dll)
# Format: { "Gol-ant-it-XXXXX": { "uid": "...", "name": "...", "created": ..., "requests": 0, "limit": 1000, "active": True } }
API_KEYS_DB: dict = {}

# ─── REQUEST STATS ───
REQUEST_LOG: list = []


# ══════════════════════════════════════════════════════════════════
#  MODELS
# ══════════════════════════════════════════════════════════════════

class GenerateRequest(BaseModel):
    prompt: str
    model: Literal["claude", "openai"] = "claude"
    mode: Literal["website", "chat"] = "website"
    stream: bool = True

class CreateKeyRequest(BaseModel):
    uid: str          # Firebase UID user
    name: str         # Nama user
    email: str        # Email user
    limit: int = 500  # Request limit

class AdminRequest(BaseModel):
    admin_secret: str


# ══════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════

def generate_api_key() -> str:
    """Generate API key format: Gol-ant-it-XXXXX"""
    chars = string.ascii_letters + string.digits
    suffix = ''.join(secrets.choice(chars) for _ in range(20))
    return f"Gol-ant-it-{suffix}"


def validate_key(api_key: str) -> dict:
    """Validasi API key, return key data atau raise HTTPException"""
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required. Header: X-SoraaAI-Key")
    
    key_data = API_KEYS_DB.get(api_key)
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if not key_data.get("active", True):
        raise HTTPException(status_code=403, detail="API key has been deactivated")
    
    if key_data["requests"] >= key_data["limit"]:
        raise HTTPException(status_code=429, detail=f"Request limit exceeded ({key_data['limit']} requests)")
    
    return key_data


def build_website_prompt(user_prompt: str) -> str:
    """Build system prompt untuk generate website"""
    return f"""You are SoraaAI, an expert web developer. Generate a COMPLETE, BEAUTIFUL, PRODUCTION-READY single HTML file website based on the user's request.

STRICT RULES:
1. Output ONLY valid HTML code — no markdown, no explanation, no backticks
2. Everything in ONE file: HTML + CSS + JS inline
3. Must be visually stunning with modern design
4. Use Google Fonts (link in <head>)
5. Fully responsive (mobile-first)
6. Add smooth animations and micro-interactions
7. Include realistic placeholder content based on the prompt
8. Use CSS custom properties (variables)
9. Dark or light theme based on context
10. Add a subtle "Built with SoraaAI" in the footer

Design requirements:
- Modern typography (not Arial/Roboto — use Syne, Cabinet Grotesk, Plus Jakarta Sans, Manrope, etc.)
- Rich color palette with gradients
- Professional layout with sections: Hero, Features/Services, About, CTA, Footer
- Glassmorphism, neumorphism, or bold flat design where appropriate
- Hover effects and transitions
- NO Lorem ipsum — write real contextual copy

User request: {user_prompt}

OUTPUT: Complete HTML file only. Start with <!DOCTYPE html>"""


def build_chat_prompt(user_prompt: str) -> str:
    return f"""You are SoraaAI, a helpful AI assistant. Answer clearly and helpfully.

User: {user_prompt}"""


# ══════════════════════════════════════════════════════════════════
#  API KEY ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/api/keys/create")
async def create_api_key(req: CreateKeyRequest):
    """
    Buat API key baru untuk user (dipanggil saat user login pertama kali via Firebase)
    """
    # Cek apakah user sudah punya key
    for key, data in API_KEYS_DB.items():
        if data.get("uid") == req.uid:
            return {
                "success": True,
                "api_key": key,
                "message": "Existing key returned",
                "data": {k: v for k, v in data.items() if k != "uid"}
            }
    
    # Generate key baru
    new_key = generate_api_key()
    API_KEYS_DB[new_key] = {
        "uid": req.uid,
        "name": req.name,
        "email": req.email,
        "created": datetime.utcnow().isoformat(),
        "requests": 0,
        "limit": req.limit,
        "active": True,
        "plan": "free"
    }
    
    return {
        "success": True,
        "api_key": new_key,
        "message": "API key created successfully",
        "data": {
            "name": req.name,
            "limit": req.limit,
            "requests": 0,
            "plan": "free",
            "created": API_KEYS_DB[new_key]["created"]
        }
    }


@app.get("/api/keys/info")
async def get_key_info(x_soraaai_key: str = Header(None)):
    """Get info tentang API key"""
    key_data = validate_key(x_soraaai_key)
    return {
        "success": True,
        "data": {
            "name": key_data["name"],
            "email": key_data["email"],
            "requests_used": key_data["requests"],
            "requests_limit": key_data["limit"],
            "requests_remaining": key_data["limit"] - key_data["requests"],
            "plan": key_data.get("plan", "free"),
            "active": key_data["active"],
            "created": key_data["created"]
        }
    }


@app.delete("/api/keys/revoke")
async def revoke_key(x_soraaai_key: str = Header(None)):
    """Revoke API key"""
    key_data = validate_key(x_soraaai_key)
    API_KEYS_DB[x_soraaai_key]["active"] = False
    return {"success": True, "message": "API key revoked"}


# ══════════════════════════════════════════════════════════════════
#  AI GENERATION ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/api/generate")
async def generate(req: GenerateRequest, x_soraaai_key: str = Header(None)):
    """
    Main generation endpoint — stream HTML website atau chat response
    """
    key_data = validate_key(x_soraaai_key)
    
    # Build prompt berdasarkan mode
    if req.mode == "website":
        full_prompt = build_website_prompt(req.prompt)
    else:
        full_prompt = build_chat_prompt(req.prompt)
    
    # Increment request counter
    API_KEYS_DB[x_soraaai_key]["requests"] += 1
    
    # Log request
    REQUEST_LOG.append({
        "key": x_soraaai_key[:20] + "...",
        "model": req.model,
        "mode": req.mode,
        "time": datetime.utcnow().isoformat(),
        "uid": key_data.get("uid", "")
    })
    
    if req.model == "claude":
        return await stream_claude(full_prompt, req.mode)
    else:
        return await stream_openai(full_prompt, req.mode)


async def stream_claude(prompt: str, mode: str):
    """Stream dari Anthropic Claude API"""
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=503, detail="Claude API key not configured on server")
    
    async def generator():
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-opus-4-5",
                    "max_tokens": 8192,
                    "stream": True,
                    "messages": [{"role": "user", "content": prompt}]
                }
            ) as response:
                if response.status_code != 200:
                    error = await response.aread()
                    yield f"data: {json.dumps({'error': error.decode()})}\n\n"
                    return
                
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str == "[DONE]":
                            yield "data: [DONE]\n\n"
                            break
                        try:
                            data = json.loads(data_str)
                            if data.get("type") == "content_block_delta":
                                delta = data.get("delta", {})
                                if delta.get("type") == "text_delta":
                                    text = delta.get("text", "")
                                    yield f"data: {json.dumps({'text': text})}\n\n"
                        except json.JSONDecodeError:
                            pass
    
    return StreamingResponse(generator(), media_type="text/event-stream")


async def stream_openai(prompt: str, mode: str):
    """Stream dari OpenAI API"""
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=503, detail="OpenAI API key not configured on server")
    
    async def generator():
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o",
                    "max_tokens": 8192,
                    "stream": True,
                    "messages": [
                        {"role": "system", "content": "You are SoraaAI, an expert web developer."},
                        {"role": "user", "content": prompt}
                    ]
                }
            ) as response:
                if response.status_code != 200:
                    error = await response.aread()
                    yield f"data: {json.dumps({'error': error.decode()})}\n\n"
                    return
                
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str == "[DONE]":
                            yield "data: [DONE]\n\n"
                            break
                        try:
                            data = json.loads(data_str)
                            choices = data.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                text = delta.get("content", "")
                                if text:
                                    yield f"data: {json.dumps({'text': text})}\n\n"
                        except json.JSONDecodeError:
                            pass
    
    return StreamingResponse(generator(), media_type="text/event-stream")


# ══════════════════════════════════════════════════════════════════
#  ADMIN ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.get("/admin/keys")
async def admin_list_keys(admin_secret: str):
    """List semua API keys (admin only)"""
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin secret")
    
    keys_summary = []
    for key, data in API_KEYS_DB.items():
        keys_summary.append({
            "key": key[:20] + "...",
            "name": data["name"],
            "email": data["email"],
            "requests": data["requests"],
            "limit": data["limit"],
            "active": data["active"],
            "created": data["created"]
        })
    
    return {"total": len(keys_summary), "keys": keys_summary}


@app.get("/admin/stats")
async def admin_stats(admin_secret: str):
    """Stats keseluruhan"""
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin secret")
    
    total_requests = sum(d["requests"] for d in API_KEYS_DB.values())
    active_keys = sum(1 for d in API_KEYS_DB.values() if d["active"])
    
    return {
        "total_users": len(API_KEYS_DB),
        "active_keys": active_keys,
        "total_requests": total_requests,
        "recent_requests": REQUEST_LOG[-50:]
    }


# ══════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "service": "SoraaAI API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "create_key": "POST /api/keys/create",
            "key_info": "GET /api/keys/info",
            "generate": "POST /api/generate",
            "health": "GET /health"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "claude_configured": bool(ANTHROPIC_API_KEY),
        "openai_configured": bool(OPENAI_API_KEY),
        "total_users": len(API_KEYS_DB),
        "timestamp": datetime.utcnow().isoformat()
    }


# ══════════════════════════════════════════════════════════════════
#  STARTUP
# ══════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event():
    print("=" * 60)
    print("  SoraaAI Backend API — Starting...")
    print(f"  Claude API: {'✓ Configured' if ANTHROPIC_API_KEY else '✗ NOT SET'}")
    print(f"  OpenAI API: {'✓ Configured' if OPENAI_API_KEY else '✗ NOT SET'}")
    print(f"  Admin Secret: {ADMIN_SECRET[:10]}...")
    print("=" * 60)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
