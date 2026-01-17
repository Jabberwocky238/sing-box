import fastapi

app = fastapi.FastAPI()

@app.post("/auth")
async def authenticate(request: fastapi.Request):
    data = await request.json()
    print(data)
    return {"ok": True, "id": "user123"}
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8888)