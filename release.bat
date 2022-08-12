set name=gogo
for /F %%i in ('git describe --abbrev^=0 --tags') do ( set gt_ver=%%i)
@REM 上传到阿里云
ossutil cp ./bin/%name%_windows_386_upxs.exe oss://sangfor-release/fscan/windows_386_upxs.exe -f
ossutil cp ./bin/%name%_windows_386s.exe oss://sangfor-release/fscan/windows_386s.exe -f
ossutil cp ./bin/%name%_windows_amd64s.exe oss://sangfor-release/fscan/windows_amd64s.exe -f
ossutil cp ./bin/%name%_windows_amd64_upxs.exe  oss://sangfor-release/fscan/windows_amd64_upxs.exe -f
ossutil cp ./bin/%name%_linux_386 oss://sangfor-release/fscan/linux_386 -f
ossutil cp ./bin/%name%_linux_arm64  oss://sangfor-release/fscan/linux_arm64 -f
ossutil cp ./bin/%name%_linux_amd64 oss://sangfor-release/fscan/linux_amd64 -f
ossutil cp ./bin/%name%_linux_mips64 oss://sangfor-release/fscan/linux_mips64 -f
ossutil cp ./bin/%name%_darwin_amd64 oss://sangfor-release/fscan/darwin_amd64 -f

@REM 打包
tar --format=ustar -zcvf release/%name%%gt_ver%.tar.gz bin/%name%* doc/* README.md *.py