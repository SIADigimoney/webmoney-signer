# webmoney-signer

WebMoney message signing for .NET without COM. One `Signer` works with keys of both schemes:
classic RSA (Keeper WinPro) and v2 (Ed25519). The repository also contains Key Extractor,
a Windows utility that extracts the signing key from a `.kwm` key file.

Based on [webmoney-signer](https://github.com/MarketKernel/webmoney-signer)
(WMSigner for .NET 4.0.0, RSA keys only).

## Features

- RSA and v2 (Ed25519) keys in one `Signer`.
- v2 messages are NFC-normalized and encoded as UTF-8 without BOM; RSA messages stay Windows-1251.
- XML key form for both schemes: `<RSAKeyValue>…</RSAKeyValue>` and
  `<Ed25519KeyValue><Seed>…</Seed></Ed25519KeyValue>`.
- Classic `.kwm` (RSA) read and write; Key Extractor reads `.kwm` of both schemes.
- Targets `netstandard2.0` and `net48`.

## Changes from the original

| | original 4.0.0 | this repository |
|---|---|---|
| version | package 4.0.0, assembly 4.0.0.0 | package 4.1.0; assembly version stays 4.0.0.0, so it is a drop-in replacement |
| key schemes | RSA | RSA and v2 (Ed25519) |
| `Signer.Initialize` | `KeeperKey` or RSA XML | also `Initialize(byte[] ed25519Seed)` and v2 XML; `IsV2` property |
| message encoding | Windows-1251 | RSA: Windows-1251; v2: NFC + UTF-8 without BOM |
| `DecryptedKey.Encrypt` without `half` | full password | first half of the password, as Keeper WinPro writes it; full password is `Encrypt(..., half: false)` |
| targets | `netstandard2.0` | `netstandard2.0` and `net48` (Windows-1251 comes from the framework, no CodePages package) |
| dependencies | System.Text.Encoding.CodePages | BouncyCastle.Cryptography 2.7.0; CodePages only for `netstandard2.0` |
| Key Extractor | RSA `.kwm`, .NET Framework 4.6.1 | RSA and v2 `.kwm`, Hex string mode, .NET Framework 4.8 |

## Projects

| project | |
|---|---|
| `WebMoney.Cryptography` | the library |
| `WebMoney.Cryptography.Tests` | MSTest unit tests, including RFC 8032 test vectors |
| `WebMoney.KeyExtractor` | Windows Forms utility, .NET Framework 4.8 |

## Quick Start

RSA key from a `.kwm` file. The password is passed as Windows-1251 bytes:

```csharp
using WebMoney.Cryptography;

byte[] password = Encoding.GetEncoding(1251).GetBytes(passwordText);

using (DecryptedKey key = DecryptedKey.Decrypt(File.ReadAllBytes(kwmPath), wmid, password))
using (Signer signer = new Signer())
{
    signer.Initialize(key);
    string signature = signer.Sign(message);   // 132 hex chars, randomized padding
}
```

Key in XML form, for example from a config file. The scheme is chosen by the root element:

```csharp
using (Signer signer = new Signer())
{
    signer.Initialize(xmlKey);                 // <RSAKeyValue> or <Ed25519KeyValue>
    string signature = signer.Sign(message);   // v2: 128 hex chars, deterministic
}
```

v2 key as raw bytes:

```csharp
using (Signer signer = new Signer())
{
    signer.Initialize(ed25519Seed);            // byte[32]; signer.IsV2 == true
    string signature = signer.Sign(message);
}

string xmlKey = Signer.ToV2XmlString(ed25519Seed);   // XML form of the same key
```

Notes:

- The scheme is chosen by the `Initialize` overload or the XML root element, never by key
  length.
- A message must not contain `\r`.
- `KeeperKey`, `DecryptedKey` and `Signer` are `IDisposable` and clear private key bytes on
  dispose. `DecryptedKey` takes ownership of the arrays passed to it, so pass copies.

## Key Extractor

Open a `.kwm` file from the menu and enter the WMID and password. The key scheme is detected
from the file header.

| output mode | RSA key | v2 key |
|---|---|---|
| Base64 | `<RSAKeyValue>` XML | `<Ed25519KeyValue>` XML |
| Base64 xml-encoded | the same XML, HTML-escaped for config files | the same |
| Hex | C# byte array literals for modulus and D | C# byte array literal for the seed |
| Hex string | `D:` and `N:` lines, 16-bit words, low word first, `%04x` each | 64 hex chars of the seed |

**Sign message** signs a test string with the loaded key. A v2 signature is deterministic and can
be used as a reference value.

The output is a private key. Keep it as secret as the `.kwm` file and its password.

## Development

Requirements: Visual Studio 2022 or Build Tools with the .NET Framework 4.8 Developer Pack, and
the .NET 8 SDK for the tests.

```
msbuild WebMoney.Cryptography.sln -restore -p:Configuration=Release
dotnet test WebMoney.Cryptography.Tests
```

## Support

support@webmoney.com

## License

MIT, Copyright (c) 2026 SIA Digimoney. See [LICENSE](LICENSE).
