echo ==================================================      >>[win]%computername%.txt
echo [W-01 Start]                  >>[win]%computername%.txt
echo [W-01 Administrator �����̸� �ٲٱ�]         >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ]  "Administrator Default"���� �̸��� ������ ���>> [win]%computername%.txt
echo [���]  "Administrator Default"���� �̸��� �������� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net user | findstr /i Administrator >nul
if %errorlevel% == 0 (
echo [���] "���� �̸� �������� ����"    >>[win]%computername%.txt
) else (
echo [��ȣ] "���� �̸� ������"    >>[win]%computername%.txt
)               
echo ==================================================      >>[win]%computername%.txt
echo W-01 END                     >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-02 Start]                  >>[win]%computername%.txt
echo [W-02 Guest ��������]         >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ]  Guest ������ ��Ȱ��ȭ �Ǿ� �ִ� ���>> [win]%computername%.txt
echo [���]  Guest ������ Ȱ��ȭ �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net user guest | find /i "Account active" | find /i "No" > nul
if %ERRORLEVEL% EQU 0 (
	echo [��ȣ] : Guest ������ ��Ȱ��ȭ �Ǿ� �ִ� ��� >>[win]%computername%.txt
)else (
	echo [���] : Guest ������ Ȱ��ȭ �Ǿ� �ִ� ��� >>[win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-02 END                     >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt

@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-03 START >>[win]%computername%.txt
echo [W-03 "���ʿ��� ���� ����"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : ���ʿ��� ������ �������� �ʴ� ��� >> [win]%computername%.txt
echo [���] : ���ʿ��� ������ �����ϴ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [���ͺ�] >> [win]%computername%.txt
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
echo [W-04] ���� ��� �Ӱ谪 ���� 				>> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] ���� ��� �Ӱ谪�� 5 �̸��� ������ ���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] ���� ���� �Ӱ谪�� 5 ������ ������ ���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt


type secedit.txt | findstr /i "lockoutbadcount" | findstr /i "1 2 3 4" >nul 2>&1
if %errorlevel% == 0 (
echo [���] 5ȸ �̸� 		>> [win]%computername%.txt
) else (
echo [��ȣ] 5ȸ �̻�   		>> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-04 END							>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt


@echo off
echo ==================================================      >>[win]%computername%.txt
echo [W-05 Start]                  >>[win]%computername%.txt
echo [W-05 "�н����� �ִ� ��� �Ⱓ ����"]               >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ]  �ִ� ��ȣ ��� �Ⱓ�� 90�� ���Ϸ� �����Ǿ� �ִ� ���>> [win]%computername%.txt
echo [���]  �ִ� ��ȣ ��� �Ⱓ�� �������� �ʾҰų� 90���� �ʰ��ϴ� ������ ������ ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
secedit /EXPORT /CFG LocalSecurityPolicy.txt
TYPE LocalSecurityPolicy.txt | find /i "MaximumPasswordAge" | find /v "\"
TYPE LocalSecurityPolicy.txt | find "MaximumPasswordAge =" >>W-05.txt
FOR /f "tokens=1-3" %%a IN (W-05.txt) DO SET passwd_maxage=%%c
IF %passwd_maxage% LEQ 90 echo [��ȣ] : �ִ� ��ȣ ��� �Ⱓ�� 90�� ���Ϸ� �����Ǿ� ���� >>[win]%computername%.txt
IF NOT %passwd_maxage% LEQ 90 echo [���] : �ִ� ��ȣ ��� �Ⱓ�� �������� �ʾҰų� 90���� �ʰ���              >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-05 END                     >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt
echo.                        >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-07 START]   >> [win]%computername%.txt
echo [W-07 "�ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ ����"]   >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] "�ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ����" ��å�� "��� �� ��" ���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] "�ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ����" ��å�� "���"���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
secedit /export /cfg c:\secedit.txt
type secedit.txt | findstr /I "ClearTextPassword" | findstr /i "0" >nul 2>&1	 
if %errorlevel% == 0 (
echo [��ȣ] ��� �� �� ���� ���� �� 	>> [win]%computername%.txt
) else (
echo [���] ��� ���� ���� ��  		>> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-07 END					 >> [win]%computername%.txt
echo ====================================== >> [win]%computername%.txt
echo.						 >> [win]%computername%.txt
echo.						 >> [win]%computername%.txt



echo ==================================================      >>[win]%computername%.txt
echo W-08 START >>[win]%computername%.txt
echo [W-08 "������ �׷쿡 �ּ����� ����� ����"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : Administrators �׷��� �������� 1�� ���Ϸ� �����ϰų�, ���ʿ��� ������ ������ �������� �ʴ� ��� >> [win]%computername%.txt
echo [���] : Administrators �׷쿡 ���ʿ��� ������ ������ �����ϴ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [���ͺ�] >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-08 END	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-09 START >>[win]%computername%.txt
echo [W-09 "���� ���� �� ����� �׷� ����"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : �Ϲ� ���� ���丮�� ���ų� ���� ���丮 ���� ���ѿ� Everyone ������ ���� ��� >> [win]%computername%.txt
echo [���] : �Ϲ� ���� ���丮�� ���� ���ѿ� Everyone ������ �ִ� ��� >> [win]%computername%.txt
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
	echo [���] : �Ϲ� ���� ���丮�� ���� ���ѿ� Everyone ������ �ִ� ��� >> [win]%computername%.txt
)else (
	echo [��ȣ] : �Ϲ� ���� ���丮�� ���ų� ���� ���丮 ���� ���ѿ� Everyone ������ ���� ��� >> [win]%computername%.txt
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
echo [W-10 "�ϵ��ũ �⺻ ���� ����"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : ������Ʈ���� AutoShareServer ^(WinNT: AutoShareWks^)�� 0�̸� �⺻ ������ �������� �ʴ� ��� >> [win]%computername%.txt
echo [���] : ������Ʈ����AutoShareServer ^(WinNT: AutoShareWks^)�� 1�̰ų� �⺻ ������ �����ϴ� ��� >> [win]%computername%.txt
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
      echo [��ȣ] : ������Ʈ���� AutoShareServer ^(WinNT: AutoShareWks^)�� 0�̸� �⺻ ������ �������� �ʴ� ��� >> [win]%computername%.txt
   )else (
      echo [���] : ������Ʈ����AutoShareServer ^(WinNT: AutoShareWks^)�� 1�� ��� >> [win]%computername%.txt
   )
)else (
   echo [���] : �⺻ ������ �����ϴ� ��� >> [win]%computername%.txt
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
echo [W-11 "���ʿ��� ���� ����"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : �Ϲ������� ���ʿ��� ���񽺰� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] : �Ϲ������� ���ʿ��� ���񽺰� ���� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net start | findstr /C:"Alerter" /C:"Automatic Updates" /C:"Clipbook" /C:"Computer Browser" /C:"Cryptographic Services" /C:"DHCP Client" /C:"Distributed Link Tracking Client Server" /C:"Error reporting Service" /C:"Human Interface Device Access" /C:"IMAPI CD-Burning COM Service" /C:"Messenger" /C:"NetMeeting Remote Desktop Sharing" /C:"Portable Media Serial Numbe" /C:"Print Spooler" /C:"Remote Registry" /C:"Simple TCP/IP Services" /C:"Wireless Zero Configuration" > nul
if %ERRORLEVEL% EQU 0 (
   echo [���] : �Ϲ������� ���ʿ��� ���񽺰� ���� ���� ��� >> [win]%computername%.txt
)else (
   echo [��ȣ] : �Ϲ������� ���ʿ��� ���񽺰� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
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
echo [W-12"NetBIOS ���ε� ���� ���� ����"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] : TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ����� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
ipconfig /all | findstr /i "NetBIOS over Tcpip" | find /i "Enabled" > nul
if %ERRORLEVEL% EQU 0 (
   echo [���] : TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ����� ���� ��� >> [win]%computername%.txt
)else (
   echo [��ȣ] : TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
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
echo [W-13 "FTP ���� ���� ����"] >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] FTP ���񽺸� ������� �ʴ� ��� �Ǵ� secure FTP ����(sFTP)�� ����ϴ� ��� >> [win]%computername%.txt
echo [���] FTP���񽺸� ����ϴ� ���  >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.			          >>[win]%computername%.txt
net start | find "Microsoft FTP Service" > nul
IF ERRORLEVEL 1 echo [��ȣ] FTP Service ��Ȱ��ȭ	>>[win]%computername%.txt
IF NOT ERRORLEVEL 1 echo [���]FTP Service Ȱ��ȭ >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-13 END			>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.				>>[win]%computername%.txt
echo.				>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-14 START] >>[win]%computername%.txt
echo [W-14 "FTP ���͸� ���ٱ��� ����"] >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] FTPȨ ���丮�� Everyone ������ ���� ��� >> [win]%computername%.txt
echo [���] FTPȨ ���丮�� Everyone ������ �ִ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt

net start | find "FTP" > nul
IF ERRORLEVEL 1 GOTO DIRACL-FTP-DISABLE
IF NOT ERRORLEVEL 1 GOTO DIRACL-FTP-ENABLE
:DIRACL-FTP-DISABLE
echo [��ȣ] FTP Service�� ��Ȱ��ȭ 		>>[win]%computername%.txt
GOTO W-14 END
:DIRACL-FTP-ENABLE
:: reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSFtpsvc\Parameters\Virtual Roots" \s   >>[win]%computername%.txt 2>&1
echo �� C:\Inetpub\ftproot ���� ���� ��	>>[win]%computername%.txt
echo.		>>[win]%computername%.txt
icacls "C:\Inetpub\ftproot" |find \v "������ ó��������"	>>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo �� �Է¹��� ftp���͸� ���� ���� �� >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo �Է¹��� ftp ���͸� : "%ftpR% "	>>[win]%computername%.txt
icacls "%ftpR%" | find /v "������ ó��������"	>>[win]%computername%.txt
:W-14 END
echo ==================================================      >>[win]%computername%.txt
echo W-14 END				>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.					>>[win]%computername%.txt
echo.					>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-15 START]	>>[win]%computername%.txt
echo [W-15 "Anonymouse FTP ����"]		 >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] FTP ���񽺸� ������� �ʰų�, "�͸� ���� ���"�� üũ���� ���� ��� >> [win]%computername%.txt
echo [���] FTP ���񽺸� ����ϰų�, "�͸� ���� ���"�� üũ�Ǿ� �ִ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		 >>[win]%computername%.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MSFTPSVC\Parameters" /s | find /I "AllowAnonymous"  >>[win]%computername%.txt 2>&1
IF ERRORLEVEL 1 echo [��ȣ] Anonymouse FTP ������� ����	>>[win]%computername%.txt
IF NOT ERRORLEVEL 1 [���]Anonymouse FTP ���  >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-15 END	 >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		 >>[win]%computername%.txt
echo.		 >>[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-16 START >>[win]%computername%.txt
echo [W-16 "FTP ���� ���� ����"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] :  Ư�� IP�ּҿ����� FTP ������ �����ϵ��� �������� ������ ������ ��� >> [win]%computername%.txt
echo [���] :  Ư�� IP�ּҿ����� FTP ������ �����ϵ��� �������� ������ �������� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [���ͺ�] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-16 END	 >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-17 START >>[win]%computername%.txt
echo [W-17"DNS Zone Transfer ����"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] :  �Ʒ� ���ؿ� �ش�� ��� >> [win]%computername%.txt
echo 1. DNS ���񽺸� ��� �ʴ� ��� >> [win]%computername%.txt
echo 2. ���� ���� ����� ���� �ʴ� ��� >> [win]%computername%.txt
echo 3. Ư�� �����θ� ������ �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] : �� 3�� ���� �� �ϳ��� �ش� ���� �ʴ� ��� >> [win]%computername%.txt
echo DatabaseFile = zone �̸� >> [win]%computername%.txt
echo SecureSecondaries = DNS Zone Transfer �������� ���� >> [win]%computername%.txt
echo SecureSecondaries = 0 ��û�ϴ� ��� secondary server(���� ����)�� zone transfer ���� >> [win]%computername%.txt
echo SecureSecondaries = 1 zone�� ���Ͽ� ������ �ִ� name server�θ� ���� >> [win]%computername%.txt
echo SecureSecondaries = 2 Ư�� �����θ� zone transfer ���� >> [win]%computername%.txt
echo SecureSecondaries = 3 zone transfer �������� ���� >> [win]%computername%.txt
echo SecureSecondaries 0,1�̸� ��� 2�̸� ��ȣ >> [win]%computername%.txt
echo SecondaryServers = ���������� ���� ���� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
net start | find /i "DNS Server" > nul
if not !ERRORLEVEL! EQU 0 (
   echo [��ȣ] : DNS ���񽺸� ������� �����Ƿ� ��ȣ�� >> [win]%computername%.txt
) else (
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr /i "SecureSecondaries" | findstr /i "0x2 0x3" > nul
   if !ERRORLEVEL! EQU 0 (
      echo [W-17] * [��ȣ] :  �Ʒ� ���ؿ� �ش�� ��� >> [win]%computername%.txt
      echo 1. DNS ���񽺸� ��� �ʴ� ��� >> [win]%computername%.txt
      echo 2. ���� ���� ����� ���� �ʴ� ��� >> [win]%computername%.txt
                echo 3. Ư�� �����θ� ������ �Ǿ� �ִ� ��� >> [win]%computername%.txt
        ) else (
      echo [���] : �� 3�� ���� �� �ϳ��� �ش� ���� �ʴ� ��� >> [win]%computername%.txt
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
echo [W-18 "RDS(RemoteDataServices) ����"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] :  IIS�� ������� �ʴ°��, ����Ʈ �� ����Ʈ�� MSADC���� ���丮�� �������� �ʴ� ���, �ش� ������Ʈ�� ���� �������� �ʴ� ��� >> [win]%computername%.txt
echo [���] :  ��ȣ ���ؿ� �� ������ �ش���� �ʴ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [���ͺ�] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-18 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-19 START >>[win]%computername%.txt
echo [W-19 "�ֽ� ���� �� ����"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] :  �ֽ� �������� ��ġ�Ǿ� ������ ���� ���� �� ����� ������ ��� >> [win]%computername%.txt
echo [���] :  �ֽ� �������� ��ġ���� �ʰų�, ���� ���� �� ����� �������� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [���ͺ�] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-19 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt



@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-20 START >>[win]%computername%.txt
echo [W-20 "���ʿ��� ���� ����"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : �ֽ� Hotfix�� �ִ��� �ֱ������� ����͸��ϰ� �ݿ��ϰų�, PMS (PatchManagement System) Agent�� ��ġ�Ǿ� �ڵ���ġ������ ����� ��� >> [win]%computername%.txt
echo [���] : �ֽ� Hotfix�� �ִ��� �ֱ������� ����� ������ ���ų�, �ֽ� Hotfix�� �ݿ����� ���� ���, ���� PMS(Patch Management System) Agent�� ��ġ�Ǿ� ���� �ʰų�, ��ġ�Ǿ� ������ �ڵ���ġ������ ������� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [���ͺ�] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-20 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo [W-21 START]	>>	[win]%computername%.txt
echo [W-21 "��� ���α׷� ������Ʈ"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] ���̷��� ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� �ְų�, �� �ݸ� ȯ���� ��� ��� ������Ʈ�� ���� ���� �� ���� ����� ������ ��� >> [win]%computername%.txt
echo [���] ���̷��� ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� ���� �ʰų�, �� �ݸ� ȯ���� ��� ��� ����Ʈ�� ���� ���� �� ���� ����� �������� ���� ��� >> [win]%computername%.txt
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
	echo [��ȣ] : ���̷��� ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� �ְų�, �� �ݸ� >>	[win]%computername%.txt
	echo ȯ���� ��� ��� ������Ʈ�� ���� ���� �� ���� ����� ������ ���>>	[win]%computername%.txt
)else (
	echo [���] : ���̷��� ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� ���� �ʰų�, >>	[win]%computername%.txt
	echo �� �ݸ� ȯ���� ��� ��� ������Ʈ�� ���� ���� �� ���� ����� �������� ���� ��� >>	[win]%computername%.txt
)

echo ==================================================      >>[win]%computername%.txt
echo W-21 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


@echo off

echo ==================================================      >>[win]%computername%.txt
echo W-22 START >>[win]%computername%.txt
echo [W-22 "�α��� ������ ���� �� ����"]	>>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] :  ���ӱ���� ���ȷα�, ���� ���α׷� �� �ý��� �α� ��Ͽ� ���� ���������� ����, �м�, ����Ʈ �ۼ� �� ���� ���� ��ġ�� �̷������ ��� >> [win]%computername%.txt
echo [���] :  �� �α� ��Ͽ� ���� ���������� ����, �м�, ����Ʈ �ۼ� �� ���� ���� ��ġ�� �̷�� ���� �ʴ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [���ͺ�] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-22 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.		>>[win]%computername%.txt
echo.		>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-23 START]	>>[win]%computername%.txt
echo [W-23 "�������� ������ �� �� �ִ� ������Ʈ�� ���"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] Remote Registry Service�� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] Remote Registry Service�� ��� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
net start | find /I "Remote Registry" && echo [���] "Remote Registry Service"�� ��� �� 	>>	[win]%computername%.txt
net start | find /I "Remote Registry" || echo [��ȣ] "Remote Registry Service"�� ������	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo W-23 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo W-24 START >>[win]%computername%.txt
echo [W-24 "��� ���α׷� ��ġ"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : ���̷��� ��� ���α׷��� ��ġ�Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] : ���̷��� ��� ���α׷��� ��ġ�Ǿ� ���� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt (
   set i=0
   for /f "delims=:" %%a in (test.txt) do (
   set /A i+=1
   set name[!i!]=%%a
   ) 
) else (
   echo [���] : ���̷��� ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� ���� �ʰų�, �� �ݸ� ȯ���� ��� ��� ������Ʈ�� ���� ���� �� ���� ����� �������� ���� ��� >> [win]%computername%.txt
   goto end
)
echo [��ȣ] : ���̷��� ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� �ְų�, �� �ݸ� ȯ���� ��� ��� ������Ʈ�� ���� ���� �� ���� ����� ������ ��� >> [win]%computername%.txt

echo ==================================================      >>[win]%computername%.txt
echo. W-24 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt
if exist test.txt del test.txt


echo ==================================================      >>[win]%computername%.txt
echo W-25 START >> [win]%computername%.txt
echo [W-25 "SAM ���� ���� ���� ����"] >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : SAM ���� ���ٱ��ѿ� Administrator, System �׷츸 ��� �������� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] : SAM ���� ���ٱ��ѿ� Administrator, System �׷� �� �ٸ� �׷쿡 ������ �����Ǿ� �ִ� ��� >> [win]%computername%.txt
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
   echo [��ȣ] : SAM ���� ���ٱ��ѿ� Administrator, System �׷츸 ��� �������� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
)else (
   echo [���] : SAM ���� ���ٱ��ѿ� Administrator, System �׷� �� �ٸ� �׷쿡 ������ �����Ǿ� �ִ� ��� >> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-25 END >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
if exist test.txt del test.txt
if exist test1.txt del test1.txt


echo [W-26 START]   >>   [win]%computername%.txt
echo [W-26 "ȭ�麸ȣ�� ����"]   >>   [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] "ȭ�� ��ȣ�⸦ �����ϰ� ��� �ð��� 10�� ������ ������ �����Ǿ� ������, ȭ�� ��ȣ�� ������ ���� ��ȣ�� ����ϴ� ���" >>[win]%computername%.txt
echo [���] "ȭ�� ��ȣ�⸦ �����ϰ� ��� �ð��� 10�� �̻��� ������ �����Ǿ� ������, ȭ�� ��ȣ�� ������ ���� ��ȣ�� ������� ���� ���"   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
reg query "HKCU\Control Panel\Desktop" /s | find /i "ScreenSaveActive" | find "0" > nul
if %ERRORLEVEL% EQU 0 (
   echo [���] : ȭ�� ��ȣ�� ������ ����Ǿ� ���� ���� ��� >> [win]%computername%.txt
   goto end
)

reg query "HKCU\Control Panel\Desktop" /s | find /i "SCRNSAVE.EXE" > nul
if %ERRORLEVEL% NEQ 0 (
   echo [���] : ȭ�� ��ȣ�� ������ ����Ǿ� ���� ���� ��� >> [win]%computername%.txt
   goto end
)

reg query "HKCU\Control Panel\Desktop" /s | find /i "ScreenSaverIsSecure" | find "0" > nul
if %ERRORLEVEL% EQU 0 (
   echo [���] : ȭ�� ��ȣ�Ⱑ �������� �ʾҰų� ��ȣ�� ������� ���� ��� �Ǵ�, ȭ�� >> [win]%computername%.txt
   echo ��ȣ�� ��� �ð��� 10���� �ʰ��� ������ �����Ǿ� �ִ� ��� >> [win]%computername%.txt
   goto end
)

reg query "HKCU\Control Panel\Desktop" /s | find /i "ScreenSaveTimeOut" > test.txt
for /f "tokens=3 delims= " %%a in (test.txt) do set a=%%a
if %a% GTR 600 (
   echo [���] ȭ�� ��ȣ�� ������ 10�� �̻��� ������ �����Ǿ� �ְų� ������ ���� ��ȣ�� ����ϰ� ���� �����Ƿ� ����� >> [win]%computername%.txt
   goto end
)

echo [��ȣ] ȭ�� ��ȣ�� ������ 10�� ������ ������ �����Ǿ� ������, ������ ���� ��ȣ�� ����ϰ� �����Ƿ� ��ȣ�� >> [win]%computername%.txt
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
echo [W-27 "�α׿� ���� �ʰ� �ý��� ���� ���"]   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] : ���α׿� ���� �ʰ� �ý��� ���� ��롱�� ����� �� �ԡ����� �����Ǿ� �ִ°�� >> [win]%computername%.txt
echo [���] : ���α׿� ���� �ʰ� �ý��� ���� ��롱�� ����롱���� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "shutdownwithoutlogon" | find "0x0" > nul
if %ERRORLEVEL% == 0 (
   echo [��ȣ] : ���α׿� ���� �ʰ� �ý��� ���� ��롱�� ����� �� �ԡ����� �����Ǿ� �ִ°�� >> [win]%computername%.txt
)else (
   echo [���] : ���α׿� ���� �ʰ� �ý��� ���� ��롱�� ����롱���� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-27 END   >>[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt
echo.      >>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-28 START]	>>	[win]%computername%.txt
echo [W-28 "���� �ý��ۿ��� ������ �ý��� ����"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] "���� �ý��ۿ��� ������ �ý��� ����"��å�� "Administrators"�� ���� �ϴ� ��� >> [win]%computername%.txt
echo [���] "���� �ý��ۿ��� ������ �ý��� ����"��å�� "Administrators"�� �ٸ� ���� �� �׷��� ���� �ϴ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
type [win]%computername%.txt | find "SeRemoteShutdownPrivilege = *S-1-5-32-544" > nul
if %ERRORLEVEL% == 0 (
   echo [��ȣ] : ������ �ý��ۿ��� ������ �ý��� ���ᡱ ��å�� ��Administrators���� ���� >>[win]%computername%.txt
   echo �ϴ� ��� >>[win]%computername%.txt
)else (
   echo [���] : ������ �ý��ۿ��� ������ �ý��� ���ᡱ ��å�� ��Administrators�� �� �ٸ� >>[win]%computername%.txt
   echo ���� �� �׷��� �����ϴ� ��� >>[win]%computername%.txt
)

echo ==================================================      >>[win]%computername%.txt
echo W-28 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>[win]%computername%.txt
echo.	>>[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-29 START]	>>	[win]%computername%.txt
echo [W-29 "���� ���縦 �α��� �� ���� ��� ��� �ý��� ����"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] "���� ���縦 �α��� �� ���� ��� ��� �ý��� ����" ��å�� "��� �� ��"���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] "���� ���縦 �α��� �� ���� ��� ��� �ý��� ����" ��å�� "���"���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "CrashOnAuditFail" | findstr /i "0x0" >nul
if %errorlevel% == 0 (
echo [��ȣ] "���� ���縦 �α��� �� ���� ��� ��� �ý��� ����"�� "��� �� ��" ����	>>[win]%computername%.txt
) else (
echo [���] "���� ���縦 �α��� �� ���� ��� ��� �ý��� ����"�� "���" ���� 	>>[win]%computername%.txt
)

echo ==================================================      >>[win]%computername%.txt
echo W-29 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-30 START]	>>	[win]%computername%.txt
echo [W-30 "SAM ������ ������ �͸� ���� ��� ����"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] �ش� ���� �ɼ� ���� ���� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] �ش� ���� �ɼ� ���� ���� �Ǿ� ���� �ʴ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "restrictanonymoussam" | findstr /i "0x1" >nul
if %errorlevel% == 0 (
echo [��ȣ] "��Ʈ��ũ �׼���: SAM������ �͸� ���� ��� �� ��"�� "���" ����	>>[win]%computername%.txt
) else (
echo [���] "��Ʈ��ũ �׼���: SAM������ �͸� ���� ��� �� ��"�� "��� �� ��" ���� 	>>[win]%computername%.txt
)
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "restrictanonymous" | findstr /i "0x1" >nul
if %errorlevel% == 0 (
echo [��ȣ] "��Ʈ��ũ �׼���: SAM������ ������ �͸� ���� ��� �� ��"�� "���" ����	>>[win]%computername%.txt
) else (
echo [���] "��Ʈ��ũ �׼���: SAM������ ������ �͸� ���� ��� �� ��"�� "��� �� ��" ���� 	>>[win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-30 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-31 START]	>>	[win]%computername%.txt
echo [W-31 "Autologon��� ����"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] "AutoAdminLogon" ���� ���ų� 0���� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] "AutoAdminLogon" ���� 1�� �����Ǿ� �ִ� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s | findstr /I "AutoAdminLogon" | findstr /i "0" >nul
if %errorlevel% == 0 (
echo [��ȣ] AutoAdminLogon ���� ���ų� 0�� ���   		>> [win]%computername%.txt
) else (
echo [���] AutoAdminLogon ���� 1�� ���      		>> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-31 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt


echo ==================================================      >>[win]%computername%.txt
echo [W-32 START]	>>	[win]%computername%.txt
echo [W-32 "�̵��� �̵�� ���� �� ������ ���"]	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo [��ȣ] "�̵��� �̵�� ���� �� ������ ���" ��å�� "Administrator"�� �Ǿ� �ִ� ��� >> [win]%computername%.txt
echo [���] "�̵��� �̵�� ���� �� ������ ���" ��å�� "Administrator"�� �Ǿ� ���� ���� ��� >> [win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
secedit /export /cfg LocalSecuritypolicy.txt >nul 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s | find  /I "AllocateDASD" | findstr /i "0" >nul
if %errorlevel% == 0 (
echo [��ȣ] Administrator ���  		>> [win]%computername%.txt
) else (
echo [���] Administrator ��� �� ��   		>> [win]%computername%.txt
)
echo ==================================================      >>[win]%computername%.txt
echo W-32 END	>>	[win]%computername%.txt
echo ==================================================      >>[win]%computername%.txt
echo.	>>	[win]%computername%.txt
echo.	>>	[win]%computername%.txt

del secedit.txt
del W-05.txt
del LocalSecurityPolicy.txt