# Build the signer binary
Set-Location .\internal\signer\windows
go build
Move-Item .\signer.exe ..\..\..\build\windows_64bit\
Set-Location ..\..\..\

# Build the signer library
go build -buildmode=c-shared -o .\build\windows_64bit\signer.dll .\cshared\main.go
Remove-Item .\build\windows_64bit\signer.h