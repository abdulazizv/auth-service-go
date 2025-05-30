FROM golang:1.24-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main ./cmd/server

RUN chmod +x run.sh

EXPOSE 3001

CMD ["./main"]
