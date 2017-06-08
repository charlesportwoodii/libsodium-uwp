msbuild ../libsodium-uwp.sln /t:Clean /p:Platform=ARM /p:Configuration=Debug
msbuild ../libsodium-uwp.sln /t:Clean /p:Platform=ARM /p:Configuration=Release
msbuild ../libsodium-uwp.sln /t:Clean /p:Platform=x86 /p:Configuration=Debug
msbuild ../libsodium-uwp.sln /t:Clean /p:Platform=x86 /p:Configuration=Release
msbuild ../libsodium-uwp.sln /t:Clean /p:Platform=x64 /p:Configuration=Debug
msbuild ../libsodium-uwp.sln /t:Clean /p:Platform=x64 /p:Configuration=Release
msbuild ../libsodium-uwp.sln /t:Build /p:Platform=ARM /p:Configuration=Debug /m /verbosity:minimal /p:OutputPath=../build/Debug/ARM
msbuild ../libsodium-uwp.sln /t:Build /p:Platform=ARM /p:Configuration=Release /m /verbosity:minimal /p:OutputPath=../build/Release/ARM
msbuild ../libsodium-uwp.sln /t:Build /p:Platform=x86 /p:Configuration=Debug /m /verbosity:minimal /p:OutputPath=../build/Debug/x86
msbuild ../libsodium-uwp.sln /t:Build /p:Platform=x86 /p:Configuration=Release /m /verbosity:minimal /p:OutputPath=../build/Release/x86
msbuild ../libsodium-uwp.sln /t:Build /p:Platform=x64 /p:Configuration=Debug /m /verbosity:minimal /p:OutputPath=../build/Debug/x64
msbuild ../libsodium-uwp.sln /t:Build /p:Platform=x64 /p:Configuration=Release /m /verbosity:minimal /p:OutputPath=../build/Release/x64
