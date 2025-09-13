# build stage
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/cot-translator ./cmd/cot-translator

# run stage (distroless)
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/cot-translator /cot-translator
EXPOSE 5010/udp
ENTRYPOINT ["/cot-translator"]
