FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /hub .

FROM scratch
COPY --from=build /hub /hub
EXPOSE 8080
ENTRYPOINT ["/hub"]
