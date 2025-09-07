FROM python:3.11-slim
WORKDIR /app
COPY RatDo.py /app/RatDo.py
RUN pip install --no-cache-dir flask
EXPOSE 5000
CMD ["python", "RatDo.py"]
