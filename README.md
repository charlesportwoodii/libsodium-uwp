# libsodium-uwp

[![AppVeyor](https://img.shields.io/appveyor/ci/charlesportwoodii/libsodium-uwp.svg?style=flat-square)](https://ci.appveyor.com/project/charlesportwoodii/libsodium-uwp)
[![License](https://img.shields.io/github/license/charlesportwoodii/libsodium-uwp.svg?style=flat-square)](https://github.com/charlesportwoodii/libsodium-uwp/blob/master/LICENSE.md)
[![Nuget](https://img.shields.io/nuget/vpre/libsodium-uwp.svg?style=flat-square)](https://www.nuget.org/packages/libsodium-uwp/)

libsodium-uwp ([libsodium](https://github.com/jedisct1/libsodium) for Universal Windows Platform (UWP)) is a C++ Windows Runtime Component for UWP applications. This library is fully tested and executes on both Windows 10 and Windows 10 mobile.

Cryptography is hard. This library was written to make libsodium available to the .NET community building Universal Windows Applications so that developers can safely and securely implement cryptography within their application.

## Requirements

- [Visual Studio 2015](https://www.visualstudio.com/vs/)

## Installation

1. Clone this project

    ```
    git clone --recursive https://github.com/charlesportwoodii/libsodium-uwp
    ```
2. Add the project solution to your project via `File->Add->Existing Project`
3. Add a reference to `libsodium-uwp` by adding `libsodium-uwp\libsodium-uwp\libsodium-uwp.vcxproj` to your project references.
4. Add a reference to `Visual C++ Redistributable for Visual Studio 2015` to your project.


### Nuget Installation

1. Install from Nuget

    ```
    Install-Package libsodium-uwp
    ```

2. Add the following to your `Package.appxmanifest` file.

    ```xml
      <Extensions>
        <Extension Category="windows.activatableClass.inProcessServer">
            <InProcessServer>
                <Path>libsodium-uwp.dll</Path>
                <ActivatableClass ActivatableClassId="Sodium.Core" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.CryptoHash" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.GenericHash" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.GenericHashAlgorithmProvider" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.GenericHashAlgorithmNames" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.KDF" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.KeyPair" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.OneTimeAuth" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.PasswordHash" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.PublicKeyAuth" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.PublicKeyBox" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.ScalarMult" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.SealedPublicKeyBox" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.SecretBox" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.SecretKeyAuth" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.SecretAead" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.SecretStream" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.ShortHash" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.StreamEncryption" ThreadingModel="both" />
                <ActivatableClass ActivatableClassId="Sodium.Utilities" ThreadingModel="both" />
            </InProcessServer>
        </Extension>
    </Extensions>
    ```

## Documentation

See the [docs](docs/) folder for complete documentation on how to use this library.

## Notes

`libsodium` requires the [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145).

This library is currently a work in progress. While many libsodium functions are implemented, not are all. See the [docs](docs/) folder for more information. Also see the [releases](/releases) page for more information and details as to what is available on Nuget, as the `master` branch may be ahead of what is available there.

## License

NaCl has been released to the public domain to avoid copyright issues. libsodium is subject to the ISC license, and this software is subject to the BSD-3 Clause License (see LICENSE.md).
