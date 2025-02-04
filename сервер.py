from contextlib import closing
from pathlib import Path
from passlib.context import CryptContext
from fastapi import FastAPI, HTTPException, Header, Path, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import mysql.connector
import jwt

# Настройка CryptContext для хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Настройки подключения к MySQL
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'sonya140505!',
    'database': 'bdh'
}

app = FastAPI()

# Настройка ключа для JWT
SECRET_KEY = "secret_key"
ALGORITHM = "HS256"

# Утилиты для работы с токенами
def create_token(user_id: int) -> str:
    """Создание токена JWT"""
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Подключение к базе данных MySQL
def get_db_connection():
    connection = mysql.connector.connect(**DB_CONFIG)
    return connection


# Pydantic модели
class UserIn(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str

class DeleteUserRequest(BaseModel):
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    password: str
    created_at: datetime


class Operation(BaseModel):
    operation: int
    result: str

class Score(BaseModel):
    result: int


# Эндпоинты
@app.post("/register", response_model=UserOut)
async def register(user: UserIn):
    print(f"Получили из окна регистрации имя пользователя username = {user.username}")
    print(f"Получили из окна регистрации пароль password = {user.password}")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
        db_user = cursor.fetchone()
        print(f"Результат запроса к БД {db_user}")
        if db_user:
            raise HTTPException(status_code=400, detail="Username already exists")

        # Хешируем пароль перед сохранением
        hashed_password = pwd_context.hash(user.password)

        cursor.execute(
            "INSERT INTO users (username, password, created_at) VALUES (%s, %s, %s)",
            (user.username, hashed_password, datetime.utcnow())  # Сохраняем хеш пароля
        )
        conn.commit()
        user_id = cursor.lastrowid
        cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
        new_user = cursor.fetchone()

        return UserOut(id=new_user[0], username=new_user[1], password=new_user[2], created_at=new_user[3])

    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.post("/login")
async def login(user: UserIn):
    print(f"Получили из окна авторизации имя пользователя username = {user.username}")
    print(f"Получили из окна авторизации пароль password = {user.password}")
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, password FROM users WHERE username = %s", (user.username,))
    db_user = cursor.fetchone()
    print(f"Результат запроса к БД {db_user}")

    if not db_user or not pwd_context.verify(user.password, db_user[2]):  # Проверка пароля
        conn.close()
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    user_id = db_user[0]  # Берем user_id
    token = create_token(user_id)
    print(f"Создали токен {token}")
    conn.close()

    return {"token": token, "id": db_user[0]}


@app.post("/save_score")
async def save_score(score: Score, authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing or invalid")

    token = authorization.split(" ")[1]
    user_id = verify_token(token)  # user_id из токена

    with closing(get_db_connection()) as conn, closing(conn.cursor()) as cursor:
        # Дополнительно можно проверить существование пользователя
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute(
            "INSERT INTO statistic (user_id, best_score, created_at) VALUES (%s, %s, %s)",
            (user_id, score.result, datetime.utcnow())  # Сохраняем лучший результат
        )
        conn.commit()

    return {"message": "Score saved successfully"}


@app.get("/get_best_score/{user_id}")
async def get_best_score(user_id: int):
    with closing(get_db_connection()) as conn, closing(conn.cursor()) as cursor:
        # Проверяем, существует ли пользователь
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        # Получаем лучший результат
        cursor.execute(
            "SELECT best_score, created_at FROM statistic WHERE user_id = %s ORDER BY best_score DESC LIMIT 1",
            (user_id,)
        )
        best_score = cursor.fetchone()

    if not best_score:
        raise HTTPException(status_code=404, detail="No scores found for this user")

    # Возвращаем результат
    return {
        "best_score": best_score[0],  # Результат
        "created_at": best_score[1]   # Время создания
    }

@app.get("/get_all_scores/{user_id}")
async def get_all_scores(user_id: int):
    with closing(get_db_connection()) as conn, closing(conn.cursor()) as cursor:
        # Проверяем, существует ли пользователь
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        # Получаем все результаты пользователя
        cursor.execute(
            "SELECT id, best_score, created_at FROM statistic WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
        scores = cursor.fetchall()

    # Формируем и возвращаем список всех результатов
    return {
        "scores": [{"id": score[0], "best_score": score[1], "created_at": score[2]} for score in scores]
    }

@app.get("/get_top_scores/{user_id}")
async def get_top_scores(user_id: int):
    with closing(get_db_connection()) as conn, closing(conn.cursor()) as cursor:
        # Получаем топ-3 лучших результатов, включая текущего пользователя
        cursor.execute("""
            SELECT u.username, MAX(s.best_score) as best_score 
            FROM statistic s
            JOIN users u ON s.user_id = u.id
            GROUP BY s.user_id
            ORDER BY best_score DESC
            LIMIT 3
        """)
        top_scores = cursor.fetchall()

    # Формируем ответ (включая текущего пользователя)
    top_scores = [
        {"username": score[0], "best_score": score[1]}
        for score in top_scores
    ]

    return {"top_scores": top_scores}


@app.post("/change_password")
async def change_password(change_password_data: ChangePasswordRequest):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, password FROM users WHERE username = %s", (change_password_data.username,))
        db_user = cursor.fetchone()

        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")

        if not pwd_context.verify(change_password_data.old_password, db_user[1]):
            raise HTTPException(status_code=401, detail="Incorrect old password")

        hashed_new_password = pwd_context.hash(change_password_data.new_password)
        cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_new_password, change_password_data.username)) # Обновляем по username
        conn.commit()

        return {"message": "Password changed successfully"}

    except mysql.connector.Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cursor.close()
        conn.close()

@app.delete("/delete_user/{username}")
async def delete_user(username: str, delete_data: DeleteUserRequest): # Новая модель для запроса
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, password FROM users WHERE username = %s", (username,))
        db_user = cursor.fetchone()

        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")

        if not pwd_context.verify(delete_data.password, db_user[1]): # Проверяем пароль
            raise HTTPException(status_code=401, detail="Incorrect password")

        cursor.execute("DELETE FROM users WHERE id = %s", (db_user[0],)) # Удаляем по id
        conn.commit()

        return {"message": "User deleted successfully"}

    except mysql.connector.Error as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cursor.close()
        conn.close()