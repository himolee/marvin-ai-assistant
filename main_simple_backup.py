from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import os

app = FastAPI(title="Marvin - Personal AI Assistant")

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Marvin AI Assistant</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            h1 { color: #333; }
            .status { color: green; font-size: 18px; }
        </style>
    </head>
    <body>
        <h1>🤖 Marvin AI Assistant</h1>
        <p class="status">✅ Successfully deployed on Render!</p>
        <p>Environment: Production</p>
        <p>Status: Running</p>
        <p>Version: 1.0.0</p>
    </body>
    </html>
    """

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "marvin-ai-assistant",
        "environment": os.getenv("RENDER", "local"),
        "secret_key_set": bool(os.getenv("SECRET_KEY"))
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
