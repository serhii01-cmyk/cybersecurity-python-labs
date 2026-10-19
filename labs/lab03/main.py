"""Головний модуль FastAPI веб-застосунку."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.config import DOMAIN_NAME, THRESHOLD, VALUE_UNIT, VARIANT_NUMBER
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ініціалізація бази даних при запуску застосунку."""
    initialize_database()
    yield


app = FastAPI(
    title=f"Web API - {DOMAIN_NAME}",
    description=(
        f"Сервіс предметної області '{DOMAIN_NAME}' (Варіант {VARIANT_NUMBER}). "
        f"Одиниця вимірювання: {VALUE_UNIT}, Поріг: {THRESHOLD}."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", tags=["System"])
def ping():
    """Перевірка доступності API."""
    return {"status": "ok"}


@app.get("/student", tags=["System"])
def student_info():
    """Відомості про студента."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
