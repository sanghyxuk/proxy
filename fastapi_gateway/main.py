from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi_utils.tasks import repeat_every
from fastapi_gateway.routes import key_issuer, stats_router
from fastapi_gateway.services.analyze_service import handle_analyze
from fastapi_gateway.cleanup_task import cleanup_expired_api_keys
from fastapi_gateway.services.auth_service import verify_api_key_and_jwt
from dotenv import load_dotenv
from fastapi.responses import JSONResponse
import os
import json

print(" FastAPI main.py 로딩됨")
app = FastAPI()

load_dotenv()

front_origin = os.getenv("FRONT_ORIGIN")
allow_origins = [front_origin] if front_origin else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 미들웨어 데코레이터 방식 등록
@app.middleware("http")
async def proxy_auth_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        # OPTIONS 요청은 인증 없이 통과
        return await call_next(request)

    path = request.url.path

    if path.startswith("/proxy/"):
        try:
            body_bytes = await request.body()
            body_str = body_bytes.decode("utf-8") if body_bytes else ""
            request.state.body = body_bytes
            request.state.body_str = body_str

            if body_str:
                request_body = json.loads(body_str)
            else:
                request_body = {}

            request_body["__raw_body__"] = body_str
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": f"요청 본문 파싱 실패: {str(e)}"})

        is_valid = await verify_api_key_and_jwt(request, request_body)
        if not is_valid:
            return JSONResponse(status_code=401, content={"error": "API Key 또는 JWT 인증 실패"})

    return await call_next(request)

# 라우터 등록
app.include_router(key_issuer.router)
app.include_router(stats_router.router)

# 분석 라우터 직접 등록
@app.post("/proxy/analyze/{target}")
async def analyze_entry(request: Request, target: str):
    return await handle_analyze(request, target)

@app.on_event("startup")
@repeat_every(seconds=86400)
async def periodic_cleanup():
    print("\U0001f9f9 API 키 자동 정리 시작")
    await cleanup_expired_api_keys()
