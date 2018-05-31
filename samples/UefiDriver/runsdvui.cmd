cd /d "C:\Users\peeprs\Desktop\VisualUefi\samples\UefiDriver" &msbuild "UefiDriver.vcxproj" /t:sdvViewer /p:configuration="Release" /p:platform=x64
exit %errorlevel% 