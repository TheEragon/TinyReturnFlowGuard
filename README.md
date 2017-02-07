# TinyReturnFlowGuard
TinyReturnFlowGuard is a minimal MSVC project that demonstrates how to enable Return Flow Guard in current builds of Microsoft Visual Studio 2017

### Requirements
- [Visual Studio 2017 RC3 (or newer)](https://www.visualstudio.com/vs/visual-studio-2017-rc/)
- [Microsoft Windows 10 15021 (or newer) SDK](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewSDK)

### Instructions
Open in Visual Studio, select ReleaseRfEnabled or ReleaseRfInstrumented, compile and enjoy RFG

### TODO
- Implement a test that would demonstrate RFG in action
- Support ReleaseRfStrict
- Exception handling in __security_check_cookie_ex and __security_check_cookie_ex_sp

License
----
MIT

Links
----
http://xlab.tencent.com/en/2016/11/02/return-flow-guard/
