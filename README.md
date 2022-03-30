# Google Proxies for Enterprise Certificates

Google Enterprise Certificate Proxies are part of the [Google Cloud Zero Trust architecture][zerotrust] that enables mutual authentication with [client-side certificates][clientcert]. This repository contains a set of proxies/modules that can be used by clients or toolings to interact with certificates that are stored in [protected key storage systems][keystore].

To interact the client certificates, application code should not need to use most of these proxies within this repository directly. Instead, the application should leverage the clients and toolings provided by Google such as [Cloud SDK](https://cloud.google.com/sdk) to have a more convenient developer experiences.

## Installation

TBD

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
