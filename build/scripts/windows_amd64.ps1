$OutputFolder = ".\build\windows_amd64"
If (Test-Path $OutputFolder) {
    # Remove existing binaries
    Remove-Item -Path ".\build\windows_amd64\*"
} else {
    # Create the folder to hold the binaries
    mkdir $OutputFolder
}

# Build the signer binary
Set-Location .\internal\signer\windows
go build
Move-Item .\signer.exe ..\..\..\build\windows_amd64\
Set-Location ..\..\..\

# Build the signer library
go build -buildmode=c-shared -o .\build\windows_amd64\signer.dll .\cshared\main.go
Remove-Item .\build\windows_amd64\signer.h
