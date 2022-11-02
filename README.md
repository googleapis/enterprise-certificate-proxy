# Google Proxies for Enterprise Certificates (Preview)

## Certificate-based-access

If you use [certificate-based access][cba] to protect your Google Cloud resources, the end user [device certificate][clientcert] is one of the credentials that is verified before access to a resource is granted. You can configure Google Cloud to use the device certificates in your operating system key store when verifying access to a resource from the gcloud CLI or Terraform by using the enterprise certificates feature.

## Google Enterprise Certificate Proxies (ECP)

Google Enterprise Certificate Proxies (ECP) are part of the [Google Cloud Zero Trust architecture](zerotrust) that enables mutual authentication with [client-side certificates][clientcert]. This repository contains a set of proxies/modules that can be used by clients or toolings to interact with certificates that are stored in [protected key storage systems][keystore].

To interact the client certificates, application code should not need to use most of these proxies within this repository directly. Instead, the application should leverage the clients and toolings provided by Google such as [Cloud SDK](https://cloud.google.com/sdk) to have a more convenient developer experience.

## Compatibility

Currently ECP is in Preview stage and all the APIs and configurations are **subject to change**.

The following platforms/keystores are supported by ECP:

- MacOS: __Keychain__
- Windows: __MyStore__
- Linux: __PKCS#11__

## Prerequisites

Before using ECP with your application/client, you should follow the instructions [here](enterprisecert) to configure your enterprise certificate policies with Access Context Manager. 

### Quick Start

1. Install [Openssl][openssl] and then add the OpenSSL installation path to your system path:
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

1. Update the `certificate_config.json` file with details about the certificate (See [Configuration](#certificate-configutation) section for details.)

1. Enable usage of client certificates through gcloud CLI config command:
```
gcloud config set context_aware/use_client_certificate true
```

1. You can now use gcloud to access GCP resources with mTLS.

### Certificate Configuration

ECP relies on the `certificate_config.json` file to read all the metadata information for locating the certificate. The contents of this JSON file look like the following:

#### MacOS (Keychain)

```json
{
  "cert_configs": {
    "macos_keychain": {
      "issuer": "YOUR_CERT_ISSUER"
    }
  },
  "libs": {
      "ecp": "~/.config/gcloud/enterprise_cert/ecp",
      "ecp_client": "~/.config/gcloud/enterprise_cert/libecp.dylib",
      "tls_offload": "~/.config/gcloud/enterprise_cert/libtls_offload.dylib"
  },
  "version": 1
}
```

#### Windows (MyStore)
```json
{
  "cert_configs": {
    "windows_store": {
      "store": "MY",
      "provider": "current_user",
      "issuer": "YOUR_CERT_ISSUER"
    }
  },
  "libs": {
      "ecp": "%AppData%/gcloud/enterprise_cert/ecp.exe",
      "ecp_client": "%AppData%/gcloud/enterprise_cert/libecp.dll",
      "tls_offload": "%AppData%/gcloud/enterprise_cert/libtls_offload.dll"
  },
  "version": 1
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
      "module": "The PKCS #11 module library file path"
    }
  },
  "libs": {
      "ecp": "~/.config/gcloud/enterprise_cert/ecp",
      "ecp_client": "~/.config/gcloud/enterprise_cert/libecp.so",
      "tls_offload": "~/.config/gcloud/enterprise_cert/libtls_offload.so"
  },
  "version": 1
}
```

## Build binaries

For amd64 MacOS, run `./build/scripts/darwin_amd64.sh`. The binaries will be placed in `build/bin/darwin_amd64` folder.

For amd64 Linux, run `./build/scripts/linux_amd64.sh`. The binaries will be placed in `build/bin/linux_amd64` folder.

For amd64 Windows, in powershell terminal, run `.\build\scripts\windows_amd64.ps1`. The binaries will be placed in `build\bin\windows_amd64` folder.
Note that gcc is required for compiling the Windows shared library. The easiest way to get gcc on Windows is to download Mingw64, and add "gcc.exe" to the powershell path.

## Contributing

Contributions to this library are always welcome and highly encouraged. See the [CONTRIBUTING](contributing) documentation for more information on how to get started.

## License

Apache - See [LICENSE](license) for more information.

[cba]: https://cloud.google.com/beyondcorp-enterprise/docs/securing-resources-with-certificate-based-access
[clientcert]: https://en.wikipedia.org/wiki/Client_certificate
[openssl]: https://wiki.openssl.org/index.php/Binaries
[keystore]: https://en.wikipedia.org/wiki/Key_management
[cloudsdk]: https://cloud.google.com/sdk
[contributing]: ./CONTRIBUTING.md
[license]:./LICENSE.md
[enterprisecert]: https://cloud.google.com/access-context-manager/docs/enterprise-certificates
