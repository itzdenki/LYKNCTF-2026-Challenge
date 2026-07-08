FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLAG="FLAG{jwt_4lg_n0ne_m4k3s_y0u_4dm1n}"

ENV JWT_SECRET="c8f3a1e9b7d24f60a1e5c9d3b6f8a2e4"

EXPOSE 3642
CMD ["gunicorn", "-b", "0.0.0.0:3642", "-w", "2", "--access-logfile", "-", "app:app"]
