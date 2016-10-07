# libsodium-uwp

libsodium-uwp ([libsodium](https://github.com/jedisct1/libsodium) for Universal Windows Platform (UWP)) is a C++ Windows Runtime Component for UWP applications. This runtime component is a work in progress 

## Installation

1. Clone this project
```
git clone --recursive https://github.com/charlesportwoodii/libsodium-uwp
```
2. Add the project solution to your project via `File->Add->Existing Project`
3. Add a reference to `libsodium-uwp` by adding `libsodium-uwp\libsodium-uwp\libsodium-uwp.vcxproj` to your project references.

## Documentation
This library can be accessed within you C# project by `using Libsodium` in your `.cs` file. See the [docs](docs/) folder for complete documentation on how to use this library.

## Notes

`libsodium` requires the [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145).

## License

NaCl has been released to the public domain to avoid copyright issues.libsodium is subject to the ISC license, and this software is subject to the BSD-3 Clause License (see LICENSE.md).