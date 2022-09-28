# Google Proxies for Enterprise Certificates (Preview)

Google Enterprise Certificate Proxies (ECP) are part of the [Google Cloud Zero Trust architecture][zerotrust] that enables mutual authentication with [client-side certificates][clientcert]. This repository contains a set of proxies/modules that can be used by clients or toolings to interact with certificates that are stored in [protected key storage systems][keystore].

To interact the client certificates, application code should not need to use most of these proxies within this repository directly. Instead, the application should leverage the clients and toolings provided by Google such as [Cloud SDK](https://cloud.google.com/sdk) to have a more convenient developer experience.

## Compatibility

Currently ECP is in Preview stage and all the APIs and configurations are **subject to change**.

The following platforms/keystores are supported by ECP:

- MacOS: __Keychain__
- Windows: __MyStore__
- Linux: __PKCS#11__

## Quick Start Guide

### Prerequisites

Before using ECP with your application/client, you should follow the instructions [here](enterprisecert) to configure your enterprise certificate policies with Access Context Manager. 

### Installation

1. Install Openssl
`brew install openssl@1.1`

1. Install gcloud CLI (Cloud SDK) at: https://cloud.google.com/sdk/docs/install

1. Download the ECP binary based on your OS from the latest [Github release](https://github.com/googleapis/enterprise-certificate-proxy/releases).

1. Unzip the downloaded zip and move all the binaries into the following directory:
   1. Windows: `%AppData%/gcloud/enterprise_cert`.
   1. Linux/MacOS: `~/.config/gcloud/enterprise_cert`.

1. If using gcloud’s bundled Python, skip to the next step. If not, install pyopenssl==22.0.0 and cryptography==36.0.2
   1. pip install cryptography==36.0.2
   1. pip install pyopenssl==22.0.0

1. Create a new JSON file at `.config/gcloud/certificate_config.json`. 
   1. Alternatively you can put the JSON in the location of your choice and set the path to it using `$ gcloud config set context_aware/enterprise_certificate_config_file_path "<json file path>"`.
   1. Another approach for setting the JSON file location is setting the location with the `GOOGLE_API_CERTIFICATE_CONFIG` environment variable.

1. Update the `certificate_config.json` file with details about the certificate (See [Configuration](#configutation) section for details.)

1. Enable usage of client certificates through gcloud CLI config command:
```
gcloud config set context_aware/use_client_certificate true
```

### Configuration

ECP relies on the `certificate_config.json` file to read all the metadata information of locating the certificate. The contents of this JSON file looks like the following:

#### MacOS (Keychain)

```json
{
  "cert_configs": {
    "macos_keychain": {
      "issuer": "YOUR_CERT_ISSUER",
    },
  },
  "libs": {
      "ecp": "~/.config/gcloud/enterprise_cert/ecp",
      "ecp_client": "~/.config/gcloud/enterprise_cert/libecp.dylib",
      "tls_offload": "~/.config/gcloud/enterprise_cert/libtls_offload.dylib",
  },
  "version": 1,
}
```

#### Windows (MyStore)
```json
{
  "cert_configs": {
    "windows_my_store": {
      "store": "MY",
      "provider": "current_user",
      "issuer": "YOUR_CERT_ISSUER",
    },
  },
  "libs": {
      "ecp": "%AppData%/gcloud/enterprise_cert/ecp.exe",
      "ecp_client": "%AppData%/gcloud/enterprise_cert/libecp.dll",
      "tls_offload": "%AppData%/gcloud/enterprise_cert/libtls_offload.dll",
  },
  "version": 1,
}
```

#### Linux (PKCS#11)
```json
{
  "cert_configs": {
    "pkcs11": {
      "label": "YOUR_TOKEN_LABEL",
      "user_pin": "YOUR_PIN",
      "slot": "YOUR_SLOT",
      "module": "The PKCS #11 module library file path",
    },
  },
  "libs": {
      "ecp": "~/.config/gcloud/enterprise_cert/ecp",
      "ecp_client": "~/.config/gcloud/enterprise_cert/libecp.so",
      "tls_offload": "~/.config/gcloud/enterprise_cert/libtls_offload.so",
  },
  "version": 1,
}
```

## Build binaries

For amd64 MacOS, run `./build/scripts/darwin_amd64.sh`. The binaries will be placed in `build/bin/darwin_amd64` folder.

For amd64 Linux, run `./build/scripts/linux_amd64.sh`. The binaries will be placed in `build/bin/linux_amd64` folder.

For amd64 Windows, in powershell terminal, run `powershell.exe .\build\scripts\windows_amd64.sh`. The binaries will be placed in `build\bin\windows_amd64` folder.

## Contributing

Contributions to this library are always welcome and highly encouraged. See the [CONTRIBUTING](contributing) documentation for more information on how to get started.

## License

Apache - See [LICENSE](license) for more information.

[zerotrust]: https://cloud.google.com/beyondcorp
[clientcert]: https://en.wikipedia.org/wiki/Client_certificate
[keystore]: https://en.wikipedia.org/wiki/Key_management
[cloudsdk]: https://cloud.google.com/sdk
[contributing]: ./CONTRIBUTING.md
[license]:./LICENSE.md
[enterprisecert]: https://cloud.google.com/access-context-manager/docs/enterprise-certificates
