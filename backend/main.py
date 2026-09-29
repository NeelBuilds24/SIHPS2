import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router

app = FastAPI(
    title="SentinelGraph API",
    description="AI-Based Detection of Cyber Threats in Unidirectional IP Traffic (PS 26145 - NTRO)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for local Streamlit integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
app.include_router(router)  # Root alias for direct endpoint access

@app.get("/")
def root():
    return {
        "message": "Welcome to SentinelGraph API",
        "documentation": "/docs",
        "health_check": "/health",
        "strict_security": "PASSIVE_ONE_WAY_MONITORING_ENCLAVE"
    }

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
