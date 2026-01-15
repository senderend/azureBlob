FROM python:3.11-slim

WORKDIR /Mythic/

RUN pip install --no-cache-dir mythic_container azure-storage-blob

COPY [".", "."]

CMD ["python3", "main.py"]
