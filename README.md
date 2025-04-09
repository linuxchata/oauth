## Overview
This authorization server provides robust OAuth2 capabilities, supporting a variety of client applications. It enables secure access management, handling access token issuance, validation, and user authorization through OAuth2 flows. The server is designed to be easily integrable, providing the necessary endpoints and functionalities to support secure and scalable authorization.

## Build Status
| Build server | Target |  Status |
|-|-|-|
| GitHub Actions | Build | [![build](https://github.com/linuxchata/oauth/actions/workflows/build.yml/badge.svg)](https://github.com/linuxchata/oauth/actions/workflows/build.yml) |
| GitHub Actions | Nuget | [![build_push_nuget](https://github.com/linuxchata/oauth/actions/workflows/build_push_nuget_sdk.yml/badge.svg)](https://github.com/linuxchata/oauth/actions/workflows/build_push_nuget_sdk.yml) |
| GitHub Actions | Nuget | [![build_push_nuget](https://github.com/linuxchata/oauth/actions/workflows/build_push_nuget_auth_server.yml/badge.svg)](https://github.com/linuxchata/oauth/actions/workflows/build_push_nuget_auth_server.yml) |

# Packages
| Package Source | Package Name | Status |
|-|-|-|
| NuGet | Shark.AuthorizationServer | [![NuGet](https://img.shields.io/nuget/v/Shark.AuthorizationServer.svg)](https://www.nuget.org/packages/Shark.AuthorizationServer/) |
| NuGet | Shark.AuthorizationServer.Sdk | [![NuGet](https://img.shields.io/nuget/v/Shark.AuthorizationServer.Sdk.svg)](https://www.nuget.org/packages/Shark.AuthorizationServer.Sdk/) |

# Specifications
- [The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [OAuth 2.0 Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591)
- [OAuth 2.0 Dynamic Client Registration Management Protocol](https://datatracker.ietf.org/doc/html/rfc7592)
- [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)
