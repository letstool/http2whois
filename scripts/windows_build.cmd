@echo off
go build ^
    -trimpath ^
    -ldflags="-s -w" ^
    -tags netgo ^
    -o .\out\http2whois.exe .\cmd\http2whois
