echo ==================================================      >>[win]%computername%.txt
echo [W-01 Start]                  >>[win]%computername%.txt
echo [W-01 Administrator 계정이름 바꾸기]         >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호]  "Administrator Default"계정 이름을 변경한 경우>> [win]%computername%.txt
echo [취약]  "Administrator Default"계정 이름을 변경하지 않은 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net user | findstr /i Administrator >nul
if %errorlevel% == 0 (
echo [취약] "계정 이름 변경하지 않음"    >>[win]%computername%.txt
) else (
echo [양호] "계정 이름 변경함"    >>[win]%computername%.txt
)               
echo ==================================================      >>[win]%computername%.txt
echo W-01 END                     >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-02 Start]                  >>[win]%computername%.txt
echo [W-02 Guest 계정상태]         >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호]  Guest 계정이 비활성화 되어 있는 경우>> [win]%computername%.txt
echo [취약]  Guest 계정이 활성화 되어 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net user guest | find /i "Account active" | find /i "No" > nul
if %ERRORLEVEL% EQU 0 (
	echo [양호] : Guest 계정이 비활성화 되어 있는 경우 >>[win]%computername%.txt
)else (
	echo [취약] : Guest 계정이 활성화 되어 있는 경우 >>[win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-02 END                     >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt

@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-03 START >>[win]%computername%.txt
echo [W-03 "불필요한 계정 제거"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : 불필요한 계정이 존재하지 않는 경우 >> [win]%computername%.txt
echo [취약] : 불필요한 계정이 존재하는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [인터뷰] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-03 END                     >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


@echo off
setlocal
chcp 437
mode con cols=80 lines=25
title Windows 2008 R2 Server Vulnerable Check Script

secedit /export /cfg secedit.txt >nul 2>&1

echo ==================================================      >>[win]%computername%.txt
echo [W-04 Start]					>>[win]%computername%.txt
echo [W-04] 계정 잠금 임계값 설정 				>> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] 계정 잠금 임계값이 5 미만의 값으로 설정 되어 있는 경우 >> [win]%computername%.txt
echo [취약] 계정 감금 임계값이 5 이하의 값으로 설정 되어 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt


type secedit.txt | findstr /i "lockoutbadcount" | findstr /i "1 2 3 4" >nul 2>&1
if %errorlevel% == 0 (
echo [취약] 5회 미만 		>> [win]%computername%.txt
) else (
echo [양호] 5회 이상   		>> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-04 END							>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt


@echo off
echo ==================================================      >>[win]%computername%.txt
echo [W-05 Start]                  >>[win]%computername%.txt
echo [W-05 "패스워드 최대 사용 기간 설정"]               >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호]  최대 암호 사용 기간이 90일 이하로 설정되어 있는 경우>> [win]%computername%.txt
echo [취약]  최대 암호 사용 기간이 설정되지 않았거나 90일을 초과하는 값으로 설정된 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
secedit /EXPORT /CFG LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "MaximumPasswordAge" | find /v "\"
TYPE LocalSecurityPolicy.txt | find "MaximumPasswordAge =" >>W-05.txt
FOR /f "tokens=1-3" %%a IN (W-05.txt) DO SET passwd_maxage=%%c
IF %passwd_maxage% LEQ 90 echo [양호] : 최대 암호 사용 기간이 90일 이하로 설정되어 있음 >>[win]%computername%.txt
IF NOT %passwd_maxage% LEQ 90 echo [취약] : 최대 암호 사용 기간이 설정되지 않았거나 90일을 초과함              >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-05 END                     >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-07 START]   >> [win]%computername%.txt
echo [W-07 "해독 가능한 암호화를 사용하여 암호 저장"]   >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] "해독 가능한 암호화를 사용하여 암호정장" 정책이 "사용 안 함" 으로 되어 있는 경우 >> [win]%computername%.txt
echo [취약] "해독 가능한 암호화를 사용하여 암호정장" 정책이 "사용"으로 되어 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
secedit /export /cfg c:\secedit.txt
type secedit.txt | findstr /I "ClearTextPassword" | findstr /i "0" >nul 2>&1	 
if %errorlevel% == 0 (
echo [양호] 사용 안 함 으로 설정 됨 	>> [win]%computername%.txt
) else (
echo [취약] 사용 으로 설정 됨  		>> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-07 END					 >> [win]%computername%.txt
echo ====================================== >> [win]%computername%.txt
echo.						 >> [win]%computername%.txt
echo.						 >> [win]%computername%.txt



echo ==================================================      >>[win]%computername%.txt
echo W-08 START >>[win]%computername%.txt
echo [W-08 "관리자 그룹에 최소한의 사용자 포함"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : Administrators 그룹의 구성원을 1명 이하로 유지하거나, 불필요한 관리자 계정이 존재하지 않는 경우 >> [win]%computername%.txt
echo [취약] : Administrators 그룹에 불필요한 관리자 계정이 존재하는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [인터뷰] >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-08 END	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-09 START >>[win]%computername%.txt
echo [W-09 "공유 권한 및 사용자 그룹 설정"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : 일반 공유 디렉토리가 없거나 공유 디렉토리 접근 권한에 Everyone 권한이 없는 경우 >> [win]%computername%.txt
echo [취약] : 일반 공유 디렉토리의 접근 권한에 Everyone 권한이 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
set flag=True
powershell -command "Get-SmbShare | Select-Object Path" | findstr -v "Path --" > test.txt
for /f "tokens=*" %%a in (test.txt) do (
	set a=%%a
	icacls "!a!" | find /i "Everyone" > nul
	if !ERRORLEVEL! EQU 0 (
		set flag=False
	)
)

if "!flag!" EQU "False" (
	echo [취약] : 일반 공유 디렉토리의 접근 권한에 Everyone 권한이 있는 경우 >> [win]%computername%.txt
)else (
	echo [양호] : 일반 공유 디렉토리가 없거나 공유 디렉토리 접근 권한에 Everyone 권한이 없는 경우 >> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-09 END	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt del test.txt
endlocal
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-10 START >>[win]%computername%.txt
echo [W-10 "하드디스크 기본 공유 제거"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : 레지스트리의 AutoShareServer ^(WinNT: AutoShareWks^)가 0이며 기본 공유가 존재하지 않는 경우 >> [win]%computername%.txt
echo [취약] : 레지스트리의AutoShareServer ^(WinNT: AutoShareWks^)가 1이거나 기본 공유가 존재하는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
set flag=False

reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /s | find /i "AutoShareServer" | find "0" >> [win]%computername%.txt
if %ERRORLEVEL% EQU 0 (
   set flag=True
   goto auto
)

reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /s | find /i "AutoShareWks" | find "0" >> [win]%computername%.txt
if %ERRORLEVEL% EQU 0 (
   set flag=True
   goto auto
)

:auto
net share | findstr /v "IPC" | find "$" > nul
if not %ERRORLEVEL% EQU 0 (
   if "%flag%" EQU "True" (
      echo [양호] : 레지스트리의 AutoShareServer ^(WinNT: AutoShareWks^)가 0이며 기본 공유가 존재하지 않는 경우 >> [win]%computername%.txt
   )else (
      echo [취약] : 레지스트리의AutoShareServer ^(WinNT: AutoShareWks^)가 1인 경우 >> [win]%computername%.txt
   )
)else (
   echo [취약] : 기본 공유가 존재하는 경우 >> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-10 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt del test.txt
endlocal
echo.      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-11 START >>[win]%computername%.txt
echo [W-11 "불필요한 서비스 제거"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : 일반적으로 불필요한 서비스가 중지되어 있는 경우 >> [win]%computername%.txt
echo [취약] : 일반적으로 불필요한 서비스가 구동 중인 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net start | findstr /C:"Alerter" /C:"Automatic Updates" /C:"Clipbook" /C:"Computer Browser" /C:"Cryptographic Services" /C:"DHCP Client" /C:"Distributed Link Tracking Client Server" /C:"Error reporting Service" /C:"Human Interface Device Access" /C:"IMAPI CD-Burning COM Service" /C:"Messenger" /C:"NetMeeting Remote Desktop Sharing" /C:"Portable Media Serial Numbe" /C:"Print Spooler" /C:"Remote Registry" /C:"Simple TCP/IP Services" /C:"Wireless Zero Configuration" > nul
if %ERRORLEVEL% EQU 0 (
   echo [취약] : 일반적으로 불필요한 서비스가 구동 중인 경우 >> [win]%computername%.txt
)else (
   echo [양호] : 일반적으로 불필요한 서비스가 중지되어 있는 경우 >> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-11 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt del test.txt
endlocal
echo.      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-12 START >>[win]%computername%.txt
echo [W-12"NetBIOS 바인딩 서비스 구동 점검"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : TCP/IP와 NetBIOS 간의 바인딩이 제거 되어 있는 경우 >> [win]%computername%.txt
echo [취약] : TCP/IP와 NetBIOS 간의 바인딩이 제거 되어있지 않은 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
ipconfig /all | findstr /i "NetBIOS over Tcpip" | find /i "Enabled" > nul
if %ERRORLEVEL% EQU 0 (
   echo [취약] : TCP/IP와 NetBIOS 간의 바인딩이 제거 되어있지 않은 경우 >> [win]%computername%.txt
)else (
   echo [양호] : TCP/IP와 NetBIOS 간의 바인딩이 제거 되어 있는 경우 >> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-12 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt del test.txt
endlocal
echo.      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-13 START] >>[win]%computername%.txt
echo [W-13 "FTP 서비스 구동 점검"] >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] FTP 서비스를 사용하지 않는 경우 또는 secure FTP 서비스(sFTP)를 사용하는 경우 >> [win]%computername%.txt
echo [취약] FTP서비스를 사용하는 경우  >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.			          >>[win]%computername%.txt
net start | find "Microsoft FTP Service" > nul
IF ERRORLEVEL 1 echo [양호] FTP Service 비활성화	>>[win]%computername%.txt
IF NOT ERRORLEVEL 1 echo [취약]FTP Service 활성화 >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-13 END			>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.				>>[win]%computername%.txt
echo.				>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-14 START] >>[win]%computername%.txt
echo [W-14 "FTP 디렉터리 접근권한 설정"] >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] FTP홈 디렉토리에 Everyone 권한이 없는 경우 >> [win]%computername%.txt
echo [취약] FTP홈 디렉토리에 Everyone 권한이 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt

net start | find "FTP" > nul
IF ERRORLEVEL 1 GOTO DIRACL-FTP-DISABLE
IF NOT ERRORLEVEL 1 GOTO DIRACL-FTP-ENABLE
:DIRACL-FTP-DISABLE
echo [양호] FTP Service가 비활성화 		>>[win]%computername%.txt
GOTO W-14 END
:DIRACL-FTP-ENABLE
:: reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSFtpsvc\Parameters\Virtual Roots" \s   >>[win]%computername%.txt 2>&1
echo ■ C:\Inetpub\ftproot 접근 권한 ■	>>[win]%computername%.txt
echo.		>>[win]%computername%.txt
icacls "C:\Inetpub\ftproot" |find \v "파일을 처리했으며"	>>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo ■ 입력받은 ftp디렉터리 접근 권한 ■ >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo 입력받은 ftp 디렉터리 : "%ftpR% "	>>[win]%computername%.txt
icacls "%ftpR%" | find /v "파일을 처리했으며"	>>[win]%computername%.txt
:W-14 END
echo ==================================================      >>[win]%computername%.txt
echo W-14 END				>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.					>>[win]%computername%.txt
echo.					>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-15 START]	>>[win]%computername%.txt
echo [W-15 "Anonymouse FTP 금지"]		 >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] FTP 서비스를 사용하지 않거나, "익명 연결 허용"이 체크되지 않은 경우 >> [win]%computername%.txt
echo [취약] FTP 서비스를 사용하거나, "익명 연결 허용"이 체크되어 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		 >>[win]%computername%.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MSFTPSVC\Parameters" /s | find /I "AllowAnonymous"  >>[win]%computername%.txt 2>&1
IF ERRORLEVEL 1 echo [양호] Anonymouse FTP 사용하지 않음	>>[win]%computername%.txt
IF NOT ERRORLEVEL 1 [취약]Anonymouse FTP 사용  >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-15 END	 >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		 >>[win]%computername%.txt
echo.		 >>[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-16 START >>[win]%computername%.txt
echo [W-16 "FTP 접근 제어 설정"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] :  특정 IP주소에서만 FTP 서버에 접속하도록 접근제어 설정이 적용한 경우 >> [win]%computername%.txt
echo [취약] :  특정 IP주소에서만 FTP 서버에 접속하도록 접근제어 설정을 적용하지 않은 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [인터뷰] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-16 END	 >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-17 START >>[win]%computername%.txt
echo [W-17"DNS Zone Transfer 설정"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] :  아래 기준에 해당될 경우 >> [win]%computername%.txt
echo 1. DNS 서비스를 사용 않는 경우 >> [win]%computername%.txt
echo 2. 영역 전송 허용을 하지 않는 경우 >> [win]%computername%.txt
echo 3. 특정 서버로만 설정이 되어 있는 경우 >> [win]%computername%.txt
echo [취약] : 위 3개 기준 중 하나라도 해당 되지 않는 경우 >> [win]%computername%.txt
echo DatabaseFile = zone 이름 >> [win]%computername%.txt
echo SecureSecondaries = DNS Zone Transfer 영역전송 여부 >> [win]%computername%.txt
echo SecureSecondaries = 0 요청하는 모든 secondary server(보조 서버)로 zone transfer 전송 >> [win]%computername%.txt
echo SecureSecondaries = 1 zone에 대하여 권한이 있는 name server로만 전송 >> [win]%computername%.txt
echo SecureSecondaries = 2 특정 서버로만 zone transfer 전송 >> [win]%computername%.txt
echo SecureSecondaries = 3 zone transfer 전송하지 않음 >> [win]%computername%.txt
echo SecureSecondaries 0,1이면 취약 2이면 양호 >> [win]%computername%.txt
echo SecondaryServers = 영역전송할 서버 내역 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net start | find /i "DNS Server" > nul
if not !ERRORLEVEL! EQU 0 (
   echo [양호] : DNS 서비스를 사용하지 않으므로 양호함 >> [win]%computername%.txt
) else (
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr /i "SecureSecondaries" | findstr /i "0x2 0x3" > nul
   if !ERRORLEVEL! EQU 0 (
      echo [W-17] * [양호] :  아래 기준에 해당될 경우 >> [win]%computername%.txt
      echo 1. DNS 서비스를 사용 않는 경우 >> [win]%computername%.txt
      echo 2. 영역 전송 허용을 하지 않는 경우 >> [win]%computername%.txt
                echo 3. 특정 서버로만 설정이 되어 있는 경우 >> [win]%computername%.txt
        ) else (
      echo [취약] : 위 3개 기준 중 하나라도 해당 되지 않는 경우 >> [win]%computername%.txt
   )
)
echo ==================================================      >>[win]%computername%.txt
echo W-17 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt del test.txt
endlocal
echo.      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-18 START >>[win]%computername%.txt
echo [W-18 "RDS(RemoteDataServices) 제거"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] :  IIS를 사용하지 않는경우, 디폴트 웹 사이트에 MSADC가상 디렉토리가 존재하지 않는 경우, 해당 레지스트리 값이 존재하지 않는 경우 >> [win]%computername%.txt
echo [취약] :  양호 기준에 한 가지도 해당되지 않는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [인터뷰] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-18 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-19 START >>[win]%computername%.txt
echo [W-19 "최신 서비스 팩 적용"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] :  최신 서비스팩이 설치되어 있으며 적용 절차 및 방법이 수립된 경우 >> [win]%computername%.txt
echo [취약] :  최신 서비스팩이 설치되지 않거나, 적용 절차 및 방법이 수립되지 않은 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [인터뷰] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-19 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt



@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-20 START >>[win]%computername%.txt
echo [W-20 "불필요한 계정 제거"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : 최신 Hotfix가 있는지 주기적으로 모니터링하고 반영하거나, PMS (PatchManagement System) Agent가 설치되어 자동패치배포가 적용된 경우 >> [win]%computername%.txt
echo [취약] : 최신 Hotfix가 있는지 주기적으로 모니터 절차가 없거나, 최신 Hotfix를 반영하지 않은 경우, 또한 PMS(Patch Management System) Agent가 설치되어 있지 않거나, 설치되어 있으나 자동패치배포가 적용되지 않은 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [인터뷰] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-20 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo [W-21 START]	>>	[win]%computername%.txt
echo [W-21 "백신 프로그램 업데이트"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립된 경우 >> [win]%computername%.txt
echo [취약] 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있지 않거나, 망 격리 환경의 경우 백신 언데이트를 위한 절차 및 적용 방법이 수립되지 않은 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt

powershell "get-ciminstance -namespace root/securitycenter2 -classname antivirusproduct | out-string -stream | select-string "productstate" | out-file -append -encoding ascii "test.txt"
type test.txt 
echo. >>	[win]%computername%.txt


for /f "tokens=2 delims=:" %%i in (test.txt) do (
	echo %%i >> test1.txt
)

for /f "delims=:" %%a in (test1.txt) do (
	powershell -NoProfile -ExecutionPolicy Bypass -File "W-19.ps1" "%%a" > nul
)

set i=0
set flag=false
for /f "delims=:" %%a in (update.txt) do (
	set /A i+=1
	if "%%a" EQU "Y" (
		set flag=True
	)
)
if "!flag!" EQU "True" (
	echo [양호] : 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 >>	[win]%computername%.txt
	echo 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립된 경우>>	[win]%computername%.txt
)else (
	echo [취약] : 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있지 않거나, >>	[win]%computername%.txt
	echo 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립되지 않은 경우 >>	[win]%computername%.txt
)

echo ==================================================      >>[win]%computername%.txt
echo W-21 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-22 START >>[win]%computername%.txt
echo [W-22 "로그의 정기적 검토 및 보고"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] :  접속기록의 보안로그, 응용 프로그램 및 시스템 로그 기록에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루어지는 경우 >> [win]%computername%.txt
echo [취약] :  위 로그 기록에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루어 지지 않는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [인터뷰] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-22 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-23 START]	>>[win]%computername%.txt
echo [W-23 "원격으로 엑세스 할 수 있는 레지스트리 경로"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] Remote Registry Service가 중지되어 있는 경우 >> [win]%computername%.txt
echo [취약] Remote Registry Service가 사용 중인 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
net start | find /I "Remote Registry" && echo [취약] "Remote Registry Service"가 사용 중 	>>	[win]%computername%.txt
net start | find /I "Remote Registry" || echo [양호] "Remote Registry Service"가 중지됨	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-23 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-24 START >>[win]%computername%.txt
echo [W-24 "백신 프로그램 설치"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : 바이러스 백신 프로그램이 설치되어 있는 경우 >> [win]%computername%.txt
echo [취약] : 바이러스 백신 프로그램이 설치되어 있지 않은 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt (
   set i=0
   for /f "delims=:" %%a in (test.txt) do (
   set /A i+=1
   set name[!i!]=%%a
   ) 
) else (
   echo [취약] : 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있지 않거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립되지 않은 경우 >> [win]%computername%.txt
   goto end
)
echo [양호] : 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립된 경우 >> [win]%computername%.txt

echo ==================================================      >>[win]%computername%.txt
echo. W-24 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt
if exist test.txt del test.txt


echo ==================================================      >>[win]%computername%.txt
echo W-25 START >> [win]%computername%.txt
echo [W-25 "SAM 파일 접근 통제 설정"] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : SAM 파일 접근권한에 Administrator, System 그룹만 모든 권한으로 설정되어 있는 경우 >> [win]%computername%.txt
echo [취약] : SAM 파일 접근권한에 Administrator, System 그룹 외 다른 그룹에 권한이 설정되어 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net localgroup Administrators > test.txt
set flag=True
for /f "tokens=2 delims=\:" %%a in (test1.txt) do (
   type test.txt | findstr /X "%%a" > nul
   if !ERRORLEVEL! EQU 1 (
      set flag=false
   )
)
if "%flag%" EQU "True" (
   echo [양호] : SAM 파일 접근권한에 Administrator, System 그룹만 모든 권한으로 설정되어 있는 경우 >> [win]%computername%.txt
)else (
   echo [취약] : SAM 파일 접근권한에 Administrator, System 그룹 외 다른 그룹에 권한이 설정되어 있는 경우 >> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-25 END >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt del test.txt
if exist test1.txt del test1.txt


echo [W-26 START]   >>   [win]%computername%.txt
echo [W-26 "화면보호기 설정"]   >>   [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] "화면 보호기를 설정하고 대기 시간이 10분 이하의 값으로 설정되어 있으며, 화면 보호기 해제를 위한 암호를 사용하는 경우" >>[win]%computername%.txt
echo [취약] "화면 보호기를 설정하고 대기 시간이 10분 이상의 값으로 설정되어 있으며, 화면 보호기 해제를 위한 암호를 사용하지 않은 경우"   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
reg query "HKCU\Control Panel\Desktop" /s | find /i "ScreenSaveActive" | find "0" > nul
if %ERRORLEVEL% EQU 0 (
   echo [취약] : 화면 보호기 설정이 적용되어 있지 않은 경우 >> [win]%computername%.txt
   goto end
)

reg query "HKCU\Control Panel\Desktop" /s | find /i "SCRNSAVE.EXE" > nul
if %ERRORLEVEL% NEQ 0 (
   echo [취약] : 화면 보호기 설정이 적용되어 있지 않은 경우 >> [win]%computername%.txt
   goto end
)

reg query "HKCU\Control Panel\Desktop" /s | find /i "ScreenSaverIsSecure" | find "0" > nul
if %ERRORLEVEL% EQU 0 (
   echo [취약] : 화면 보호기가 설정되지 않았거나 암호를 사용하지 않은 경우 또는, 화면 >> [win]%computername%.txt
   echo 보호기 대기 시간이 10분을 초과한 값으로 설정되어 있는 경우 >> [win]%computername%.txt
   goto end
)

reg query "HKCU\Control Panel\Desktop" /s | find /i "ScreenSaveTimeOut" > test.txt
for /f "tokens=3 delims= " %%a in (test.txt) do set a=%%a
if %a% GTR 600 (
   echo [취약] 화면 보호기 설정이 10분 이상의 값으로 설정되어 있거나 해제를 위한 암호를 사용하고 있지 않으므로 취약함 >> [win]%computername%.txt
   goto end
)

echo [양호] 화면 보호기 설정이 10분 이하의 값으로 설정되어 있으며, 해제를 위한 암호를 사용하고 있으므로 양호함 >> [win]%computername%.txt
:end

echo. >> [win]%computername%.txt
if exist test.txt del test.txt

echo ==================================================      >>[win]%computername%.txt
echo W-26 END   >>   [win]%computername%.txt 
echo ==================================================      >>[win]%computername%.txt
echo.   >>   [win]%computername%.txt 
echo.   >>   [win]%computername%.txt 


echo ==================================================      >>[win]%computername%.txt
echo W-27 START	>>[win]%computername%.txt
echo [W-27 "로그온 하지 않고 시스템 종료 허용"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] : “로그온 하지 않고 시스템 종료 허용”이 “사용 안 함”으로 설정되어 있는경우 >> [win]%computername%.txt
echo [취약] : “로그온 하지 않고 시스템 종료 허용”이 “사용”으로 설정되어 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "shutdownwithoutlogon" | find "0x0" > nul
if %ERRORLEVEL% == 0 (
   echo [양호] : “로그온 하지 않고 시스템 종료 허용”이 “사용 안 함”으로 설정되어 있는경우 >> [win]%computername%.txt
)else (
   echo [취약] : “로그온 하지 않고 시스템 종료 허용”이 “사용”으로 설정되어 있는 경우 >> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-27 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-28 START]	>>	[win]%computername%.txt
echo [W-28 "원격 시스템에서 강제로 시스템 종료"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] "원격 시스템에서 강제로 시스템 종료"정책에 "Administrators"만 존재 하는 경우 >> [win]%computername%.txt
echo [취약] "원격 시스템에서 강제로 시스템 종료"정책에 "Administrators"외 다른 계정 및 그룹이 존재 하는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
type [win]%computername%.txt | find "SeRemoteShutdownPrivilege = *S-1-5-32-544" > nul
if %ERRORLEVEL% == 0 (
   echo [양호] : “원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators”만 존재 >>[win]%computername%.txt
   echo 하는 경우 >>[win]%computername%.txt
)else (
   echo [취약] : “원격 시스템에서 강제로 시스템 종료” 정책에 “Administrators” 외 다른 >>[win]%computername%.txt
   echo 계정 및 그룹이 존재하는 경우 >>[win]%computername%.txt
)

echo ==================================================      >>[win]%computername%.txt
echo W-28 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>[win]%computername%.txt
echo.	>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-29 START]	>>	[win]%computername%.txt
echo [W-29 "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료" 정책이 "사용 안 함"으로 되어 있는 경우 >> [win]%computername%.txt
echo [취약] "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료" 정책이 "사용"으로 되어 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "CrashOnAuditFail" | findstr /i "0x0" >nul
if %errorlevel% == 0 (
echo [양호] "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료"에 "사용 안 함" 선택	>>[win]%computername%.txt
) else (
echo [취약] "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료"에 "사용" 선택 	>>[win]%computername%.txt
)

echo ==================================================      >>[win]%computername%.txt
echo W-29 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-30 START]	>>	[win]%computername%.txt
echo [W-30 "SAM 계정과 공유의 익명 열거 허용 안함"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] 해당 보안 옵션 값이 설정 되어 있는 경우 >> [win]%computername%.txt
echo [취약] 해당 보안 옵션 값이 설정 되어 있지 않는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "restrictanonymoussam" | findstr /i "0x1" >nul
if %errorlevel% == 0 (
echo [양호] "네트워크 액세스: SAM계정의 익명 열거 허용 안 함"에 "사용" 선택	>>[win]%computername%.txt
) else (
echo [취약] "네트워크 액세스: SAM계정의 익명 열거 허용 안 함"에 "사용 안 함" 선택 	>>[win]%computername%.txt
)
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "restrictanonymous" | findstr /i "0x1" >nul
if %errorlevel% == 0 (
echo [양호] "네트워크 액세스: SAM계정과 공유의 익명 열거 허용 안 함"에 "사용" 선택	>>[win]%computername%.txt
) else (
echo [취약] "네트워크 액세스: SAM계정과 공유의 익명 열거 허용 안 함"에 "사용 안 함" 선택 	>>[win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-30 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-31 START]	>>	[win]%computername%.txt
echo [W-31 "Autologon기능 제어"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] "AutoAdminLogon" 값이 없거나 0으로 설정되어 있는 경우 >> [win]%computername%.txt
echo [취약] "AutoAdminLogon" 값이 1로 설정되어 있는 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s | findstr /I "AutoAdminLogon" | findstr /i "0" >nul
if %errorlevel% == 0 (
echo [양호] AutoAdminLogon 값이 없거나 0일 경우   		>> [win]%computername%.txt
) else (
echo [취약] AutoAdminLogon 값이 1인 경우      		>> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-31 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-32 START]	>>	[win]%computername%.txt
echo [W-32 "이동식 미디어 포맷 및 꺼내기 허용"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [양호] "이동식 미디어 포맷 및 꺼내기 허용" 정책이 "Administrator"로 되어 있는 경우 >> [win]%computername%.txt
echo [취약] "이동식 미디어 포맷 및 꺼내기 허용" 정책이 "Administrator"로 되어 있지 않은 경우 >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s | find  /I "AllocateDASD" | findstr /i "0" >nul
if %errorlevel% == 0 (
echo [양호] Administrator 사용  		>> [win]%computername%.txt
) else (
echo [취약] Administrator 사용 안 함   		>> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-32 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt

del secedit.txt
del W-05.txt
del LocalSecurityPolicy.txt