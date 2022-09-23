$OutputFolder = ".\build\bin\windows_amd64"
If (Test-Path $OutputFolder) {
    # Remove existing binaries
    Remove-Item -Path ".\build\bin\windows_amd64\*"
} else {
    # Create the folder to hold the binaries
    New-Item -Path $OutputFolder -ItemType Directory -Force
}

# Build the signer binary
Set-Location .\internal\signer\windows
go build
Move-Item .\signer.exe ..\..\..\build\bin\windows_amd64\ecp.exe
Set-Location ..\..\..\

# Build the signer library
go build -buildmode=c-shared -o .\build\bin\windows_amd64\libecp.dll .\cshared\main.go
Remove-Item .\build\bin\windows_amd64\libecp.h
