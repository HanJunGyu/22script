import boto3
import io
import json
from difflib import SequenceMatcher
import sys
import time


class Colors: 
    BLACK = '\033[30m' 
    RED = '\033[38;5;9m'   #상
    DARKORANGE = '\033[38;5;208m'   #중
    GOLD = '\033[38;5;220m'   #하
    GREEN = '\033[32m'
    LIGHTGREEN = '\033[38;5;40m'   #KICS
    DEEPPINK = '\033[38;5;161m'
    PURPLE = '\033[38;5;129m'
    MEDIUMPURPLE = '\033[38;5;140m'   #22st
    DARKBLUE = '\033[38;5;20m'   
    YELLOW = '\033[33m' 
    BLUE = '\033[34m' 
    MAGENTA = '\033[35m' 
    CYAN = '\033[36m' 
    WHITE = '\033[37m' 
    UNDERLINE = '\033[4m' 
    RESET = '\033[0m'
    BACK_BLACK = '\033[40m'
    BACK_RED = '\033[41m'
    BACK_GREEN = '\033[42m'
    BACK_YELLOW = '\033[43m'
    BACK_BLUE = '\033[44m'
    BACK_MAGENTA = '\033[45m'
    BACK_CYAN = '\033[46m'
    BACK_WHITE = '\033[47m'

#-------------------------------------------------------------------------------------------------------

print ("")
print (Colors.MEDIUMPURPLE + "                    .d8888b.    .d8888b.                     ")
print ("                   d88P  Y88b  d88P  Y88b                    ")
print ("                          888         888                    ")
print ("                       .d88P       .d88P  .d8888b  88  .8P    ")
print ("                   .od888P'    .od888P'   88K      88.a8'    ")
print ("                  d88P'       d88P'       'Y8888b. 8888.     ")
print ("                  888'        888'             X88 88''8b.   ")
print ("                  88888888888 88888888888 '88888P' 88  '8b   " + Colors.RESET)

head = '취중진단조 AWS 취약점 진단 ver1.0'
print ("")
print ("="*75)
print ('\033[1m' + head.center(65,' ') + Colors.RESET)
print ("="*75)
print ("")
print ("")

#-------------------------------------------------------------------------------------------------------

client = boto3.client('iam') 

ec2_client = boto3.client('ec2') 

rds_client = boto3.client('rds')

s3_client = boto3.client('s3')

ct_client = boto3.client('cloudtrail')

cw_client = boto3.client('logs')

#-------------------------------------------------------------------------------------------------------

high_cnt = 0

medium_cnt = 0

low_cnt = 0

#-------------------------------------------------------------------------------------------------------

print ('\033[1m' + "[1] 계정관리" + Colors.RESET)

users = client.list_users()

count = 0

for key in users['Users']:
    #print (key['UserName'])
    List_of_Policies =  client.list_attached_user_policies(UserName=key['UserName'])
    for key in List_of_Policies['AttachedPolicies']:
        #print (key['PolicyName'])
        #print("")
        if key['PolicyName'] == 'AdministratorAccess' :
            count += 1
    
#print(count)   

if count > 1:
    high_cnt += 1
    print ("-"*75)
    print ("1.1 관리자 계정 최소화 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 관리자 권한을 부여받은 계정이 2개 이상 존재합니다.")
    print ("-"*75)
    print ("")
else:
    print ("-"*75)
    print ("1.1 관리자 계정 최소화 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("설명 : 관리자 권한이 사용 목적에 맞게 부여되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

stre = []
cnt = 0
users = client.list_users()
for key in users['Users']:
    stre.append(key['UserName'])

#print (stre)

for p1, p2 in zip(stre, stre[1:]):
    ratio = SequenceMatcher(None, p1, p2).ratio()
    #print(ratio)
    if ratio > 0.5 :
        cnt += 1

if cnt >= 1 :
    high_cnt += 1
    print ("-"*75)
    print ("1.2 IAM 사용자 계정 단일화 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 한 사용자가 2개 이상의 계정을 가지고 있습니다.")
    print ("-"*75)
    print ("")
else:
    print ("-"*75)
    print ("1.2 IAM 사용자 계정 단일화 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 1인 1계정 규칙에 맞게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------


usercnt = 0
taguser = 0 

users = client.list_users()

for key in users['Users']:
    usercnt += 1
    cnt2 = 0
    #print("")
    #print (key['UserName'])
    List_user_tags = client.list_user_tags(UserName=key['UserName'])
    for key in List_user_tags['Tags']:
        #print (key['Value'])
        if cnt2 == 0:
            taguser += 1
        cnt2 += 1
        
#print(usercnt)
#print(taguser)

nottaguser = usercnt - taguser

#print(nottaguser)
            
if usercnt != taguser:
    medium_cnt += 1
    print ("-"*75)
    print ("1.3 IAM 사용자 계정 식별 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 사용자 태그를 설정하지 않은 계정이 1개 이상 존재합니다.")
    print ("-"*75)
    print ("")

elif usercnt == taguser:
    print ("-"*75)
    print ("1.3 IAM 사용자 계정 식별 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 계정이 태그 설정이 되어 있습니다.")
    print ("-"*75)
    print ("")


#-------------------------------------------------------------------------------------------------------

cnt1 = 0
cnt2 = 0

AWS_REGION = "ap-northeast-2"

EC2_RESOURCE = boto3.resource('ec2', region_name=AWS_REGION)

key_pairs = EC2_RESOURCE.key_pairs.all()

for key in key_pairs:
    #print(f'SSH key "{key.key_name}" fingerprint: {key.key_fingerprint}')
    cnt1 += 1

EC2_RESOURCE = boto3.resource('ec2', region_name=AWS_REGION)

instances = EC2_RESOURCE.instances.all()

for instance in instances:
    #print(f'EC2 instance {instance.id}')
    cnt2 += 1

if cnt1 != cnt2 :
    high_cnt += 1
    print ("-"*75)
    print ("1.4 Key Pair 접근 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 한 개 이상의 인스턴스가 Key Pair(PEM)가 아닌 일반 패스워드로 \n       EC2 인스턴스에 접근하고 있습니다.")
    print ("-"*75)
    print ("")
elif cnt1 == cnt2:
    print ("-"*75)
    print ("1.4 Key Pair 접근 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 인스턴스가 Key Pair를 통해 EC2 인스턴스에 접근하고 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

AWS_REGION = "ap-northeast-2"

client_s3_bucket = boto3.client("s3", region_name=AWS_REGION)

response = client_s3_bucket.list_buckets()

#print("Listing Amazon S3 Buckets:")

keycnt = 0

for bucket in response['Buckets']:
    #print(f"-- {bucket['Name']}")
    S3_BUCKET_NAME = bucket['Name']

    s3_resource = boto3.resource("s3", region_name=AWS_REGION)

    s3_bucket = s3_resource.Bucket(S3_BUCKET_NAME)

    #print('Listing Amazon S3 Bucket objects/files:')

    for obj in s3_bucket.objects.all():
        #print(f'-- {obj.key}')
        if "pem" in obj.key:
            #print("success")
            keycnt += 1
            #print(keycnt)

if keycnt >= 1:
    high_cnt += 1
    print ("-"*75)
    print ("1.5 Key Pair 보관 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : Public S3 공간에 Key Pair(PEM) 파일이 저장되어 있습니다.")
    print ("-"*75)
    print ("")

elif keycnt == 0:
    print ("-"*75)
    print ("1.5 Key Pair 보관 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : Key Pair(PEM) 파일이 보관 위치가 쉽게 유추할 수 없는 공간에 \n       보관되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

cnt3 = 0
cnt4 = 0

users = client.list_users()

for key in users['Users']:
    cnt3 += 1
    #print (key['UserName'])
    List_of_MFA_Devices = client.list_mfa_devices(UserName=key['UserName'])
    for key in List_of_MFA_Devices['MFADevices']:
        cnt4 += 1
        
if cnt3 > cnt4: 
    medium_cnt += 1
    print ("-"*75)
    print ("1.6 MFA(Multi-Factor Authentication)\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : MFA 설정을 하지 않은 계정이 1개 이상 존재합니다.")
    print ("-"*75)
    print ("")
elif cnt3 == cnt4:
    print ("-"*75)
    print ("1.6 MFA(Multi-Factor Authentication)\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 계정이 MFA 설정이 되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

print ("")
print ('\033[1m' + "[2] 권한관리" + Colors.RESET)
groups = client.list_groups()

str1 = 'ec2'
str2 = 'EC2'

groupcnt = 0 
policycnt = 0
samecnt = 0

for key in groups['Groups']:
    groupnamecnt = 0
    #print ("")
    #print (key['GroupName'])
    if key['GroupName'].find(str1) == 0 or key['GroupName'].find(str2) == 0:
        groupnamecnt += 1
        groupcnt += 1
        #print (groupnamecnt)
        List_of_Policies =  client.list_attached_group_policies(GroupName=key['GroupName'])
        for key in List_of_Policies['AttachedPolicies']:
            #print (key['PolicyName'])
            if key['PolicyName'].find(str2):
                policycnt += 1
                if groupnamecnt <= policycnt:
                    samecnt += 1

#print (groupcnt)
#print (samecnt)

if groupcnt > samecnt: 
    high_cnt += 1
    print ("-"*75)
    print ("2.1 인스턴스 보안 정책 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 인스턴스 서비스 IAM 권한이 맞게 설정되어 있지 않습니다.")
    print ("-"*75)
    print ("")
elif groupcnt <= samecnt:
    print ("-"*75)
    print ("2.1 인스턴스 보안 정책 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 인스턴스 서비스 IAM 권한이 맞게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

groups = client.list_groups()

str1 = 'rds'
str2 = 'RDS'

groupcnt = 0
policycnt = 0
samecnt = 0

for key in groups['Groups']:
    groupnamecnt = 0
    #print ("")
    #print (key['GroupName'])
    if key['GroupName'].find(str1) == 0 or key['GroupName'].find(str2) == 0:
        groupnamecnt += 1
        groupcnt += 1
        #print (groupnamecnt)
        List_of_Policies =  client.list_attached_group_policies(GroupName=key['GroupName'])
        for key in List_of_Policies['AttachedPolicies']:
            #print (key['PolicyName'])
            if key['PolicyName'].find(str2):
                policycnt += 1
                if groupnamecnt <= policycnt:
                    samecnt += 1

#print (groupcnt)
#print (samecnt)

if groupcnt > samecnt: 
    high_cnt += 1
    print ("-"*75)
    print ("2.2 RDS 보안 정책 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : RDS 서비스 IAM 권한이 맞게 설정되어 있지 않습니다.")
    print ("-"*75)
    print ("")
elif groupcnt <= samecnt:
    print ("-"*75)
    print ("2.2 RDS 보안 정책 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : RDS 서비스 IAM 권한이 맞게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

groups = client.list_groups()

str1 = 's3'
str2 = 'S3'

groupcnt = 0 
policycnt = 0
samecnt = 0

for key in groups['Groups']:
    groupnamecnt = 0
    #print ("")
    #print (key['GroupName'])
    if key['GroupName'].find(str1) == 0 or key['GroupName'].find(str2) == 0:
        groupnamecnt += 1
        groupcnt += 1
        #print (groupnamecnt)
        List_of_Policies =  client.list_attached_group_policies(GroupName=key['GroupName'])
        for key in List_of_Policies['AttachedPolicies']:
            #print (key['PolicyName'])
            if key['PolicyName'].find(str2):
                policycnt += 1
                if groupnamecnt <= policycnt:
                    samecnt += 1    

#print (groupcnt)
#print (samecnt)

if groupcnt > samecnt:
    high_cnt += 1 
    print ("-"*75)
    print ("2.3 S3 보안 정책 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : S3 서비스 IAM 사용 권한이 각각 서비스 역할에 맞게 설정되어 있지 않습니다.")
    print ("-"*75)
    print ("")
elif groupcnt <= samecnt:
    print ("-"*75)
    print ("2.3 S3 보안 정책 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : S3 서비스 IAM 사용 권한이 각각 서비스 역할에 맞게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

users = client.list_users()

keycnt = 0

for key in users['Users']:
    #print("")
    #print (key['UserName'])
    List_of_Policies =  client.list_access_keys(UserName=key['UserName'])
    for key in List_of_Policies['AccessKeyMetadata']:
        #print (key['AccessKeyId'])
        keycnt += 1

#print(keycnt)

if keycnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("2.4 Access Key 정책 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : AWS Root 계정 및 IAM 계정에 Access Key가 존재합니다.")
    print ("-"*75)
    print ("")

elif keycnt == 0:
    print ("-"*75)
    print ("2.4 Access Key 정책 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : AWS Root 계정 및 IAM 계정에 Access Key키가 존재하지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

print ("")
print ('\033[1m' + "[3] 데이터관리" + Colors.RESET)

ec2 = boto3.resource('ec2',"ap-northeast-2")

volumes = ec2.volumes.all()

volumecnt = 0
encryptioncnt = 0

for key in volumes:
    #print (key.id)
    volumecnt += 1
    encryption = ec2_client.describe_volumes(VolumeIds=[key.id])
    for key in encryption['Volumes']:
        #print(key['Encrypted'])
        if key['Encrypted'] == True:
            encryptioncnt += 1

#print(volumecnt)
#print(encryptioncnt)

if volumecnt > encryptioncnt:
    medium_cnt += 1
    print ("-"*75)
    print ("3.1 인스턴스 암호화 설정\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : EC2 인스턴스 스토리지 내 한 개 이상의 블록 디바이스 암호화가 \n       비활성화되어 있습니다.")
    print ("-"*75)
    print ("")

elif volumecnt == encryptioncnt:
    print ("-"*75)
    print ("3.1 인스턴스 암호화 설정\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : EC2 인스턴스 스토리지 내 모든 블록 디바이스 암호화가 활성화되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

encrypted_cnt = 0
db_instance_cnt = 0

rds_client = boto3.client('rds')
response = rds_client.describe_db_instances()
for db_instance in response['DBInstances']:
        db_instance_cnt += 1
        db_storageencrypted = db_instance['StorageEncrypted']
        if db_storageencrypted == True:
            encrypted_cnt += 1

#print(encrypted_cnt)

if db_instance_cnt > encrypted_cnt:
    medium_cnt += 1
    print ("-"*75)
    print ("3.2 RDS 암호화 설정\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 1개 이상의 RDS 스토리지가 암호화가 활성화되어있지 않습니다.")
    print ("-"*75)
    print ("")

elif db_instance_cnt == encrypted_cnt:
    print ("-"*75)
    print ("3.2 RDS 암호화 설정\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 RDS 스토리지 암호화가 활성화되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

response = s3_client.list_buckets()
buckets = [bucket['Name'] for bucket in response['Buckets']]

bucket_cnt = 0
encrypt_cnt = 0

for bucket in buckets:
    bucket_cnt += 1
    try:
        bucket = s3_client.get_bucket_encryption(Bucket=bucket)
        encrypt_cnt += 1
    except s3_client.exceptions.ClientError: #버킷에 기본 암호화 구성이 없는 경우 GetBucketEncryption은 ServerSideEncryptionConfigurationNotFoundError 를 반환하는것을 예외처리
        medium_cnt += 1
        print ("-"*75)
        print ("3.3 S3 암호화 설정\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
        print ("")
        print ("설명 : 1개 이상의 S3 버킷이 암호화가 활성화되어있지 않습니다.")
        print ("-"*75)
        print ("")
        break

if bucket_cnt == encrypt_cnt:
    print ("-"*75)
    print ("3.3 S3 암호화 설정\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 S3 버킷이 암호화가 활성화되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

print ("")
print ('\033[1m' + "[4] 가상 리소스 관리" + Colors.RESET)
any_cnt = 0

security_groups_rules =ec2_client.describe_security_group_rules()

for key in security_groups_rules['SecurityGroupRules']:

    Security_Group_Rule_Id = key['SecurityGroupRuleId']
    Security_Group_Id = key['GroupId']
    Security_Group_From_Port = key['FromPort']
    Security_Group_To_Port = key['ToPort']
    #print(Security_Group_Id)
    #print(Security_Group_Rule_Id)
    #print(Security_Group_From_Port)
    #print(Security_Group_To_Port)
    if Security_Group_From_Port == -1:
        any_cnt += 1

#print (any_cnt)

if any_cnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("4.1 보안그룹 인/아웃바운드 ANY 설정 관리\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 1개 이상의 보안그룹 인/아웃바운드 규칙 포트 범위가 전체로 \n       허용되어 있습니다.")
    print ("-"*75)
    print ("")

elif any_cnt == 0:
    print ("-"*75)
    print ("4.1 보안그룹 인/아웃바운드 ANY 설정 관리\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 보안그룹  인/아웃바운드 규칙 포트 범위가 전체로 허용되어 \n       있지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

open_cnt = 0

security_groups_rules =ec2_client.describe_security_group_rules()

for key in security_groups_rules['SecurityGroupRules']:
    try:
        Security_Group_Rule_Id = key['SecurityGroupRuleId']
        Security_Group_Id = key['GroupId']
        Security_Group_From_Port = key['FromPort']
        Security_Group_To_Port = key['ToPort']
        Security_Group_Ipv4 = str(key['CidrIpv4'])
        #print(Security_Group_Id)
        #print(Security_Group_Rule_Id)
        #print(Security_Group_From_Port)
        #print(Security_Group_To_Port)
        #print(Security_Group_Ipv4)
        #print ("")
        if Security_Group_From_Port == -1 and Security_Group_Ipv4 == '0.0.0.0/0':
            open_cnt += 1
    except Exception:
        continue

#print (open_cnt)

if open_cnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("4.2 보안그룹 인/아웃바운드 불필요 정책 관리\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : EC2 인스턴스에 대한 인/아웃바운드 소스와 목적지의 불필요한 \n       정책이 허용되어 있습니다.")
    print ("-"*75)
    print ("")

elif open_cnt == 0:
    print ("-"*75)
    print ("4.2 보안그룹 인/아웃바운드 불필요 정책 관리\t중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : EC2 인스턴스에 대한 인/아웃바운드 소스와 목적지의 불필요한 \n       정책이 허용되어 있지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

traffic_cnt = 0

network_acl_rules = ec2_client.describe_network_acls()


for i in network_acl_rules['NetworkAcls']:
    #print ("NetworkAclId : "+i['NetworkAclId'])
    for j in i['Entries']:
        #print ("Protocol: "+j['Protocol']+" "+"RuleAction : "+j['RuleAction'])
        if j['Protocol'] == '-1' and j['RuleAction'] == 'allow':
            traffic_cnt += 1

#print (traffic_cnt)

if traffic_cnt > 0:
    high_cnt += 1
    print ("-"*75)
    print ("4.3 ACL 네트워크 인/아웃바운드 트래픽 정책 관리\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 1개 이상의 Network ACL 인/아웃바운드 규칙에 대한 모든 트래픽이 \n       허용되어 있습니다.")
    print ("-"*75)
    print ("")

elif traffic_cnt == 0:
    print ("-"*75)
    print ("4.3 ACL 네트워크 인/아웃바운드 트래픽 정책 관리\t\t중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 Network ACL 인/아웃바운드 규칙에 대한 모든 트래픽이 허용되어 \n       있지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

any_cnt = 0

network_acl_rules = ec2_client.describe_route_tables()


for i in network_acl_rules['RouteTables']:
    #print ("RouteTableId : "+i['RouteTableId'])
    for j in i['Routes']:
        #print ("DestinationCidrBlock: "+j['DestinationCidrBlock']+" ")
        #print ("")
        if j['DestinationCidrBlock'] == '0.0.0.0/0':
            any_cnt += 1

#print (any_cnt)

if any_cnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("4.4 라우팅 테이블 정책 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 1개 이상의 목적지가 ANY로 설정되어 있습니다.")
    print ("-"*75)
    print ("")

elif any_cnt == 0:
    print ("-"*75)
    print ("4.4 라우팅 테이블 정책 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 목적지가 ANY 미설정 되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

Verify = True

igw = ec2_client.describe_internet_gateways()

instance = ec2_client.describe_instances()

try:
    for i in igw['InternetGateways']:
        if Verify == True:
            Verify_True_cnt = 0
            #print (i['InternetGatewayId'])
            for j in i['Attachments']:
                #print (j['VpcId'])
                #print("")
                for k in instance['Reservations']:
                    for l in k['Instances']:
                        #print(l['VpcId'])
                        if j['VpcId'] == l['VpcId']:
                            Verify = True
                            Verify_True_cnt += 1
                        else:
                            Verify = False



        elif Verify == False:
            low_cnt += 1
            print ("-"*75)
            print ("4.6 인터넷 게이트웨이 연결 관리\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
            print ("")
            print ("설명 : 다수의 인터넷 게이트웨이 관리 시 연결된 VPC내 인스턴스가 \n       존재하지 않습니다.")
            print ("-"*75)
            print ("")
            Verify_True_cnt = 0
            break

except KeyError:
    print ("종류된 인스턴스가 있습니다")

#print (Verify)
#print (Verify_True_cnt)

if Verify_True_cnt > 0:
    print ("-"*75)
    print ("4.6 인터넷 게이트웨이 연결 관리\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 다수의 인터넷 게이트웨이 관리 시 연결된 VPC내 인스턴스가 존재합니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

bucket = s3_client.list_buckets()

bucket_cnt = 0
acl_cnt = 0

for i in bucket['Buckets']:
    bucket_cnt += 1
    #print("")
    #print(i['Name'])
    try:
        List_public_access = s3_client.get_public_access_block(Bucket=i['Name'])
        for j in List_public_access['PublicAccessBlockConfiguration']:
            acl_cnt += 1
            #print (j[0:100])

    except s3_client.exceptions.ClientError:
        medium_cnt += 1
        print ("-"*75)
        print ("4.7 S3 버킷 접근 관리\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
        print ("")
        print ("설명 : 한개 이상의 버킷 권한에서 퍼블릭 액세스 차단이 해제되어 있습니다.")
        print ("-"*75)
        print ("")
        break

#print (bucket_cnt)
#print (acl_cnt)

acl_devide_cnt = int(acl_cnt/4)
#print (acl_devide_cnt)

if bucket_cnt == acl_devide_cnt:
    print ("-"*75)
    print ("4.7 S3 버킷 접근 관리\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 버킷의 퍼블릭 액세스 차단이 활성화되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

users = client.list_users()

user_iam_cnt = 0

groups_iam_cnt = 0

for key in users['Users']:
    #print("")
    #print (key['UserName'])
    List_of_Policies =  client.list_attached_user_policies(UserName=key['UserName'])
    for key in List_of_Policies['AttachedPolicies']:
        #print (key['PolicyName'])
        if key['PolicyName'] == 'AmazonRDSFullAccess' or key['PolicyName'] == 'AmazonRDSDirectoryServiceAccess' or key['PolicyName'] == 'AmazonRDSDataFullAccess' or key['PolicyName'] == 'AmazonRDSReadOnlyAccess' or key['PolicyName'] == 'AmazonRDSEnhancedMonitoringRole':
            user_iam_cnt += 1

for i in users['Users']:
    #print("")
    #print (i['UserName'])
    List_of_Groups =  client.list_groups_for_user(UserName=i['UserName'])
    for j in  List_of_Groups['Groups']:
        #print (j['GroupName'])
        List_of_GroupsPolicy =  client.list_attached_group_policies(GroupName=j['GroupName'])
        for k in List_of_GroupsPolicy['AttachedPolicies']:
            #print (k['PolicyName'])
            if k['PolicyName'] == 'AmazonRDSFullAccess' or k['PolicyName'] == 'AmazonRDSDirectoryServiceAccess' or k['PolicyName'] == 'AmazonRDSDataFullAccess' or k['PolicyName'] == 'AmazonRDSReadOnlyAccess' or k['PolicyName'] == 'AmazonRDSEnhancedMonitoringRole':
                groups_iam_cnt += 1

#print (user_iam_cnt)
#print (groups_iam_cnt)

if user_iam_cnt > 0 or groups_iam_cnt > 0:
    print ("-"*75)
    print ("4.8 RDS 리소스 액세스 권한 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : root 계정 관리자가 다수 사용자에게 RDS 리소스 생성 권한을 \n       설정했습니다.")
    print ("-"*75)
    print ("")

elif user_iam_cnt == 0 or groups_iam_cnt == 0:
    print ("-"*75)
    print ("4.8 RDS 리소스 액세스 권한 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : root 계정 관리자가 다수 사용자에게 RDS 리소스 생성 권한을 \n       설정하지 않았습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

users = client.list_users()

user_iam_cnt = 0

groups_iam_cnt = 0

for key in users['Users']:
    #print("")
    #print (key['UserName'])
    List_of_Policies =  client.list_attached_user_policies(UserName=key['UserName'])
    for key in List_of_Policies['AttachedPolicies']:
        #print (key['PolicyName'])
        if key['PolicyName'] == 'AmazonRDSFullAccess' or key['PolicyName'] == 'AmazonRDSDirectoryServiceAccess' or key['PolicyName'] == 'AmazonRDSDataFullAccess' or key['PolicyName'] == 'AmazonRDSReadOnlyAccess' or key['PolicyName'] == 'AmazonRDSEnhancedMonitoringRole':
            user_iam_cnt += 1

for i in users['Users']:
    #print("")
    #print (i['UserName'])
    List_of_Groups =  client.list_groups_for_user(UserName=i['UserName'])
    for j in  List_of_Groups['Groups']:
        #print (j['GroupName'])
        List_of_GroupsPolicy =  client.list_attached_group_policies(GroupName=j['GroupName'])
        for k in List_of_GroupsPolicy['AttachedPolicies']:
            #print (k['PolicyName'])
            if k['PolicyName'] == 'AmazonRDSFullAccess' or k['PolicyName'] == 'AmazonRDSDirectoryServiceAccess' or k['PolicyName'] == 'AmazonRDSDataFullAccess' or k['PolicyName'] == 'AmazonRDSReadOnlyAccess':
                groups_iam_cnt += 1

#print (user_iam_cnt)
#print (groups_iam_cnt)

if user_iam_cnt > 0 or groups_iam_cnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("4.9 RDS API 작업 권한 관리 \t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 한 개 이상의 IAM 일반 사용자 권한에 RDS API 기능을 사용할 수 있는 \n       권한이 부여되어 있습니다.")
    print ("-"*75)
    print ("")

elif user_iam_cnt == 0 or groups_iam_cnt == 0:
    print ("-"*75)
    print ("4.9 RDS API 작업 권한 관리 \t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : IAM 일반 사용자 권한에 RDS API 기능을 사용할 수 있는 권한이 \n       부여되어 있지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

rds_assoc_cnt = 0

rds_sub_cnt = 0

subents = ec2_client.describe_subnets()

rds_db_subnet_group = rds_client.describe_db_subnet_groups()

for key in subents['Subnets'] :
    for tag in key['Tags']:
        if tag['Key'] == 'Name':
            if tag['Value'].find('RDS') >= 0 or tag['Value'].find('rds') >= 0:
                #print(tag['Value'])
                #print(key['SubnetId'])
                #print("")
                for rds in rds_db_subnet_group['DBSubnetGroups']:
                    #print(rds['DBSubnetGroupName'])
                    for sub in rds['Subnets']:
                        #print(sub['SubnetIdentifier'])
                        if key['SubnetId'] == sub['SubnetIdentifier']:
                            rds_assoc_cnt += 1

for rds in rds_db_subnet_group['DBSubnetGroups']:
                    for sub in rds['Subnets']:
                        rds_sub_cnt += 1

#print(rds_sub_cnt)
#print(rds_assoc_cnt)

if rds_sub_cnt > rds_assoc_cnt:
    medium_cnt += 1
    print ("-"*75)
    print ("4.10 RDS 서브넷 가용 영역 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 가상 인스턴스와 RDS 연결 간의 불필요한 서브넷이 설정되어 있습니다.")
    print ("-"*75)
    print ("")

elif rds_sub_cnt == rds_assoc_cnt:
    print ("-"*75)
    print ("4.10 RDS 서브넷 가용 영역 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 가상 인스턴스와 RDS 연결 간의 서브넷이 올바르게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

print ("")
print ('\033[1m' + "[5] 감사/추적 관리" + Colors.RESET)

ad_log_cnt = 0

cloudtrails = ct_client.describe_trails()

for i in cloudtrails['trailList']:
    try:
        #print (i['Name'])
        #print (i['S3BucketName'])
        #print (i['TrailARN'])
        #print (i['CloudWatchLogsLogGroupArn'])
        ad_log_cnt += 1
        if ad_log_cnt > 0:
            low_cnt += 1
            print ("-"*75)
            print ("5.1 AWS 사용자 계정 로깅 설정\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
            print ("")
            print ("설명 : 사용자 계정 로그 추적이 활성화 되어 있습니다.")
            print ("-"*75)
            print ("")
            break

    except KeyError:
        print ("-"*75)
        print ("5.1 AWS 사용자 계정 로깅 설정\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
        print ("")
        print ("설명 : 사용자 계정 로그 추적을 설정이 필요합니다.")
        print ("-"*75)
        print ("")
        break
    
#-------------------------------------------------------------------------------------------------------

str1 = 'aws-cloudtrail-logs'
ec2_log_cnt = 0

log_name = cw_client.describe_log_groups()
for i in log_name['logGroups']:
    #print (i['logGroupName']) 
    if i['logGroupName'].find(str1) == 0:
        ec2_log_cnt += 1

#print (ec2_log_cnt)

if ec2_log_cnt == 0:
    low_cnt += 1
    print ("-"*75)
    print ("5.2 가상 인스턴스 로깅 설정\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 가상 인스턴스 로그를 별도로 보관(물리적/논리적)하는 정책이 존재하고 있지 않습니다.")
    print ("-"*75)
    print ("")

elif ec2_log_cnt > 0:
    print ("-"*75)
    print ("5.2 가상 인스턴스 로깅 설정\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 가상 인스턴스 로그를 별도로 보관(물리적/논리적)하는 정책이 존재합니다.")
    print ("-"*75)
    print ("")


#-------------------------------------------------------------------------------------------------------

rds_instance = 0
rds_log_cnt = 0

rds_client = boto3.client('rds')
response = rds_client.describe_db_instances()
for db_instance in response['DBInstances']:
    #print("")
    #print (db_instance['DBInstanceIdentifier'])
    rds_instance += 1
    rds_log = rds_client.describe_db_log_files(DBInstanceIdentifier=db_instance['DBInstanceIdentifier'])
    for i in rds_log['DescribeDBLogFiles']:
        #print (i['LogFileName'])
        rds_log_cnt += 1
        break

#print (rds_instance)
#print (rds_log_cnt)

if rds_instance != rds_log_cnt:
    low_cnt += 1
    print ("-"*75)
    print ("5.3 RDS 로깅 설정\t\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : RDS 로그를 별도로 보관(물리적/논리적)하는 정책이 존재하고 있지 않습니다.")
    print ("-"*75)
    print ("")

elif rds_instance == rds_log_cnt:
    print ("-"*75)
    print ("5.3 RDS 로깅 설정\t\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : RDS 로그를 별도로 보관(물리적/논리적)하는 정책이 존재합니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

bucket = s3_client.list_buckets()

public_access_cnt = 0 

for i in bucket['Buckets']:
    #print("")
    #print(i['Name'])
    List_public_access = s3_client.get_bucket_logging(Bucket=i['Name'])
    if 'LoggingEnabled' not in List_public_access:
        #print('server_public_access : False')
        public_access_cnt += 1

#print (public_access_cnt)
        
if public_access_cnt > 0:
    print ("-"*75)
    print ("5.4 S3 버킷 로깅 설정\t\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 한 개 이상이 S3 버킷이 서버 액세스 로킹 활성화가 되어 있지 않습니다.")
    print ("-"*75)
    print ("")

elif public_access_cnt == 0:
    print ("-"*75)
    print ("5.4 S3 버킷 로깅 설정\t\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 S3 버킷이 서버 액세스 로킹 활성화가 되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------
total = 26

vulnerability = high_cnt + medium_cnt + low_cnt
good = total - vulnerability

print ("-"*75)
print ("총 26 / " + Colors.RED + "취약 " + str(vulnerability) + Colors.LIGHTGREEN + " / 양호 " + str(good) + Colors.RESET)
print (Colors.RED + "상 : " + str(high_cnt) + Colors.RESET) 
print (Colors.DARKORANGE + "중 : " + str(medium_cnt) + Colors.RESET)
print (Colors.GOLD + "하 : " + str(low_cnt) + Colors.RESET)
print ("-"*75)
#-------------------------------------------------------------------------------------------------------


timestr = time.strftime("%m%d%H%M")

sys.stdout = open('AWS-check-report-' + timestr +'.txt', 'w', encoding='utf-8')
#-------------------------------------------------------------------------------------------------------

high_cnt = 0

medium_cnt = 0

low_cnt = 0

#-------------------------------------------------------------------------------------------------------

print ('\033[1m' + "[1] 계정관리" + Colors.RESET)

users = client.list_users()

count = 0

for key in users['Users']:
    #print (key['UserName'])
    List_of_Policies =  client.list_attached_user_policies(UserName=key['UserName'])
    for key in List_of_Policies['AttachedPolicies']:
        #print (key['PolicyName'])
        #print("")
        if key['PolicyName'] == 'AdministratorAccess' :
            count += 1
    
#print(count)   

if count > 1:
    high_cnt += 1
    print ("-"*75)
    print ("1.1 관리자 계정 최소화 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 관리자 권한을 부여받은 계정이 2개 이상 존재합니다.")
    print ("-"*75)
    print ("")
else:
    print ("-"*75)
    print ("1.1 관리자 계정 최소화 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("설명 : 관리자 권한이 사용 목적에 맞게 부여되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

stre = []
cnt = 0
users = client.list_users()
for key in users['Users']:
    stre.append(key['UserName'])

#print (stre)

for p1, p2 in zip(stre, stre[1:]):
    ratio = SequenceMatcher(None, p1, p2).ratio()
    #print(ratio)
    if ratio > 0.5 :
        cnt += 1

if cnt >= 1 :
    high_cnt += 1
    print ("-"*75)
    print ("1.2 IAM 사용자 계정 단일화 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 한 사용자가 2개 이상의 계정을 가지고 있습니다.")
    print ("-"*75)
    print ("")
else:
    print ("-"*75)
    print ("1.2 IAM 사용자 계정 단일화 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 1인 1계정 규칙에 맞게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------


usercnt = 0
taguser = 0 

users = client.list_users()

for key in users['Users']:
    usercnt += 1
    cnt2 = 0
    #print("")
    #print (key['UserName'])
    List_user_tags = client.list_user_tags(UserName=key['UserName'])
    for key in List_user_tags['Tags']:
        #print (key['Value'])
        if cnt2 == 0:
            taguser += 1
        cnt2 += 1
        
#print(usercnt)
#print(taguser)

nottaguser = usercnt - taguser

#print(nottaguser)
            
if usercnt != taguser:
    medium_cnt += 1
    print ("-"*75)
    print ("1.3 IAM 사용자 계정 식별 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 사용자 태그를 설정하지 않은 계정이 1개 이상 존재합니다.")
    print ("-"*75)
    print ("")

elif usercnt == taguser:
    print ("-"*75)
    print ("1.3 IAM 사용자 계정 식별 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 계정이 태그 설정이 되어 있습니다.")
    print ("-"*75)
    print ("")


#-------------------------------------------------------------------------------------------------------

cnt1 = 0
cnt2 = 0

AWS_REGION = "ap-northeast-2"

EC2_RESOURCE = boto3.resource('ec2', region_name=AWS_REGION)

key_pairs = EC2_RESOURCE.key_pairs.all()

for key in key_pairs:
    #print(f'SSH key "{key.key_name}" fingerprint: {key.key_fingerprint}')
    cnt1 += 1

EC2_RESOURCE = boto3.resource('ec2', region_name=AWS_REGION)

instances = EC2_RESOURCE.instances.all()

for instance in instances:
    #print(f'EC2 instance {instance.id}')
    cnt2 += 1

if cnt1 != cnt2 :
    high_cnt += 1
    print ("-"*75)
    print ("1.4 Key Pair 접근 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 한 개 이상의 인스턴스가 Key Pair(PEM)가 아닌 일반 패스워드로 \n       EC2 인스턴스에 접근하고 있습니다.")
    print ("-"*75)
    print ("")
elif cnt1 == cnt2:
    print ("-"*75)
    print ("1.4 Key Pair 접근 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 인스턴스가 Key Pair를 통해 EC2 인스턴스에 접근하고 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

AWS_REGION = "ap-northeast-2"

client_s3_bucket = boto3.client("s3", region_name=AWS_REGION)

response = client_s3_bucket.list_buckets()

#print("Listing Amazon S3 Buckets:")

keycnt = 0

for bucket in response['Buckets']:
    #print(f"-- {bucket['Name']}")
    S3_BUCKET_NAME = bucket['Name']

    s3_resource = boto3.resource("s3", region_name=AWS_REGION)

    s3_bucket = s3_resource.Bucket(S3_BUCKET_NAME)

    #print('Listing Amazon S3 Bucket objects/files:')

    for obj in s3_bucket.objects.all():
        #print(f'-- {obj.key}')
        if "pem" in obj.key:
            #print("success")
            keycnt += 1
            #print(keycnt)

if keycnt >= 1:
    high_cnt += 1
    print ("-"*75)
    print ("1.5 Key Pair 보관 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : Public S3 공간에 Key Pair(PEM) 파일이 저장되어 있습니다.")
    print ("-"*75)
    print ("")

elif keycnt == 0:
    print ("-"*75)
    print ("1.5 Key Pair 보관 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : Key Pair(PEM) 파일이 보관 위치가 쉽게 유추할 수 없는 공간에 \n       보관되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

cnt3 = 0
cnt4 = 0

users = client.list_users()

for key in users['Users']:
    cnt3 += 1
    #print (key['UserName'])
    List_of_MFA_Devices = client.list_mfa_devices(UserName=key['UserName'])
    for key in List_of_MFA_Devices['MFADevices']:
        cnt4 += 1
        
if cnt3 > cnt4: 
    medium_cnt += 1
    print ("-"*75)
    print ("1.6 MFA(Multi-Factor Authentication)\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : MFA 설정을 하지 않은 계정이 1개 이상 존재합니다.")
    print ("-"*75)
    print ("")
elif cnt3 == cnt4:
    print ("-"*75)
    print ("1.6 MFA(Multi-Factor Authentication)\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 계정이 MFA 설정이 되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

print ("")
print ('\033[1m' + "[2] 권한관리" + Colors.RESET)
groups = client.list_groups()

str1 = 'ec2'
str2 = 'EC2'

groupcnt = 0 
policycnt = 0
samecnt = 0

for key in groups['Groups']:
    groupnamecnt = 0
    #print ("")
    #print (key['GroupName'])
    if key['GroupName'].find(str1) == 0 or key['GroupName'].find(str2) == 0:
        groupnamecnt += 1
        groupcnt += 1
        #print (groupnamecnt)
        List_of_Policies =  client.list_attached_group_policies(GroupName=key['GroupName'])
        for key in List_of_Policies['AttachedPolicies']:
            #print (key['PolicyName'])
            if key['PolicyName'].find(str2):
                policycnt += 1
                if groupnamecnt <= policycnt:
                    samecnt += 1

#print (groupcnt)
#print (samecnt)

if groupcnt > samecnt: 
    high_cnt += 1
    print ("-"*75)
    print ("2.1 인스턴스 보안 정책 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 인스턴스 서비스 IAM 권한이 맞게 설정되어 있지 않습니다.")
    print ("-"*75)
    print ("")
elif groupcnt <= samecnt:
    print ("-"*75)
    print ("2.1 인스턴스 보안 정책 관리\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 인스턴스 서비스 IAM 권한이 맞게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

groups = client.list_groups()

str1 = 'rds'
str2 = 'RDS'

groupcnt = 0
policycnt = 0
samecnt = 0

for key in groups['Groups']:
    groupnamecnt = 0
    #print ("")
    #print (key['GroupName'])
    if key['GroupName'].find(str1) == 0 or key['GroupName'].find(str2) == 0:
        groupnamecnt += 1
        groupcnt += 1
        #print (groupnamecnt)
        List_of_Policies =  client.list_attached_group_policies(GroupName=key['GroupName'])
        for key in List_of_Policies['AttachedPolicies']:
            #print (key['PolicyName'])
            if key['PolicyName'].find(str2):
                policycnt += 1
                if groupnamecnt <= policycnt:
                    samecnt += 1

#print (groupcnt)
#print (samecnt)

if groupcnt > samecnt: 
    high_cnt += 1
    print ("-"*75)
    print ("2.2 RDS 보안 정책 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : RDS 서비스 IAM 권한이 맞게 설정되어 있지 않습니다.")
    print ("-"*75)
    print ("")
elif groupcnt <= samecnt:
    print ("-"*75)
    print ("2.2 RDS 보안 정책 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : RDS 서비스 IAM 권한이 맞게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

groups = client.list_groups()

str1 = 's3'
str2 = 'S3'

groupcnt = 0 
policycnt = 0
samecnt = 0

for key in groups['Groups']:
    groupnamecnt = 0
    #print ("")
    #print (key['GroupName'])
    if key['GroupName'].find(str1) == 0 or key['GroupName'].find(str2) == 0:
        groupnamecnt += 1
        groupcnt += 1
        #print (groupnamecnt)
        List_of_Policies =  client.list_attached_group_policies(GroupName=key['GroupName'])
        for key in List_of_Policies['AttachedPolicies']:
            #print (key['PolicyName'])
            if key['PolicyName'].find(str2):
                policycnt += 1
                if groupnamecnt <= policycnt:
                    samecnt += 1    

#print (groupcnt)
#print (samecnt)

if groupcnt > samecnt:
    high_cnt += 1 
    print ("-"*75)
    print ("2.3 S3 보안 정책 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : S3 서비스 IAM 사용 권한이 각각 서비스 역할에 맞게 설정되어 있지 않습니다.")
    print ("-"*75)
    print ("")
elif groupcnt <= samecnt:
    print ("-"*75)
    print ("2.3 S3 보안 정책 관리\t\t\t\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : S3 서비스 IAM 사용 권한이 각각 서비스 역할에 맞게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

users = client.list_users()

keycnt = 0

for key in users['Users']:
    #print("")
    #print (key['UserName'])
    List_of_Policies =  client.list_access_keys(UserName=key['UserName'])
    for key in List_of_Policies['AccessKeyMetadata']:
        #print (key['AccessKeyId'])
        keycnt += 1

#print(keycnt)

if keycnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("2.4 Access Key 정책 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : AWS Root 계정 및 IAM 계정에 Access Key가 존재합니다.")
    print ("-"*75)
    print ("")

elif keycnt == 0:
    print ("-"*75)
    print ("2.4 Access Key 정책 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : AWS Root 계정 및 IAM 계정에 Access Key키가 존재하지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

print ("")
print ('\033[1m' + "[3] 데이터관리" + Colors.RESET)

ec2 = boto3.resource('ec2',"ap-northeast-2")

volumes = ec2.volumes.all()

volumecnt = 0
encryptioncnt = 0

for key in volumes:
    #print (key.id)
    volumecnt += 1
    encryption = ec2_client.describe_volumes(VolumeIds=[key.id])
    for key in encryption['Volumes']:
        #print(key['Encrypted'])
        if key['Encrypted'] == True:
            encryptioncnt += 1

#print(volumecnt)
#print(encryptioncnt)

if volumecnt > encryptioncnt:
    medium_cnt += 1
    print ("-"*75)
    print ("3.1 인스턴스 암호화 설정\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : EC2 인스턴스 스토리지 내 한 개 이상의 블록 디바이스 암호화가 \n       비활성화되어 있습니다.")
    print ("-"*75)
    print ("")

elif volumecnt == encryptioncnt:
    print ("-"*75)
    print ("3.1 인스턴스 암호화 설정\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : EC2 인스턴스 스토리지 내 모든 블록 디바이스 암호화가 활성화되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

encrypted_cnt = 0
db_instance_cnt = 0

rds_client = boto3.client('rds')
response = rds_client.describe_db_instances()
for db_instance in response['DBInstances']:
        db_instance_cnt += 1
        db_storageencrypted = db_instance['StorageEncrypted']
        if db_storageencrypted == True:
            encrypted_cnt += 1

#print(encrypted_cnt)

if db_instance_cnt > encrypted_cnt:
    medium_cnt += 1
    print ("-"*75)
    print ("3.2 RDS 암호화 설정\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 1개 이상의 RDS 스토리지가 암호화가 활성화되어있지 않습니다.")
    print ("-"*75)
    print ("")

elif db_instance_cnt == encrypted_cnt:
    print ("-"*75)
    print ("3.2 RDS 암호화 설정\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 RDS 스토리지 암호화가 활성화되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

response = s3_client.list_buckets()
buckets = [bucket['Name'] for bucket in response['Buckets']]

bucket_cnt = 0
encrypt_cnt = 0

for bucket in buckets:
    bucket_cnt += 1
    try:
        bucket = s3_client.get_bucket_encryption(Bucket=bucket)
        encrypt_cnt += 1
    except s3_client.exceptions.ClientError: #버킷에 기본 암호화 구성이 없는 경우 GetBucketEncryption은 ServerSideEncryptionConfigurationNotFoundError 를 반환하는것을 예외처리
        medium_cnt += 1
        print ("-"*75)
        print ("3.3 S3 암호화 설정\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
        print ("")
        print ("설명 : 1개 이상의 S3 버킷이 암호화가 활성화되어있지 않습니다.")
        print ("-"*75)
        print ("")
        break

if bucket_cnt == encrypt_cnt:
    print ("-"*75)
    print ("3.3 S3 암호화 설정\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 S3 버킷이 암호화가 활성화되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

print ("")
print ('\033[1m' + "[4] 가상 리소스 관리" + Colors.RESET)
any_cnt = 0

security_groups_rules =ec2_client.describe_security_group_rules()

for key in security_groups_rules['SecurityGroupRules']:

    Security_Group_Rule_Id = key['SecurityGroupRuleId']
    Security_Group_Id = key['GroupId']
    Security_Group_From_Port = key['FromPort']
    Security_Group_To_Port = key['ToPort']
    #print(Security_Group_Id)
    #print(Security_Group_Rule_Id)
    #print(Security_Group_From_Port)
    #print(Security_Group_To_Port)
    if Security_Group_From_Port == -1:
        any_cnt += 1

#print (any_cnt)

if any_cnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("4.1 보안그룹 인/아웃바운드 ANY 설정 관리\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 1개 이상의 보안그룹 인/아웃바운드 규칙 포트 범위가 전체로 \n       허용되어 있습니다.")
    print ("-"*75)
    print ("")

elif any_cnt == 0:
    print ("-"*75)
    print ("4.1 보안그룹 인/아웃바운드 ANY 설정 관리\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 보안그룹  인/아웃바운드 규칙 포트 범위가 전체로 허용되어 \n       있지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

open_cnt = 0

security_groups_rules =ec2_client.describe_security_group_rules()

for key in security_groups_rules['SecurityGroupRules']:
    try:
        Security_Group_Rule_Id = key['SecurityGroupRuleId']
        Security_Group_Id = key['GroupId']
        Security_Group_From_Port = key['FromPort']
        Security_Group_To_Port = key['ToPort']
        Security_Group_Ipv4 = str(key['CidrIpv4'])
        #print(Security_Group_Id)
        #print(Security_Group_Rule_Id)
        #print(Security_Group_From_Port)
        #print(Security_Group_To_Port)
        #print(Security_Group_Ipv4)
        #print ("")
        if Security_Group_From_Port == -1 and Security_Group_Ipv4 == '0.0.0.0/0':
            open_cnt += 1
    except Exception:
        continue

#print (open_cnt)

if open_cnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("4.2 보안그룹 인/아웃바운드 불필요 정책 관리\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : EC2 인스턴스에 대한 인/아웃바운드 소스와 목적지의 불필요한 \n       정책이 허용되어 있습니다.")
    print ("-"*75)
    print ("")

elif open_cnt == 0:
    print ("-"*75)
    print ("4.2 보안그룹 인/아웃바운드 불필요 정책 관리\t중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : EC2 인스턴스에 대한 인/아웃바운드 소스와 목적지의 불필요한 \n       정책이 허용되어 있지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

traffic_cnt = 0

network_acl_rules = ec2_client.describe_network_acls()


for i in network_acl_rules['NetworkAcls']:
    #print ("NetworkAclId : "+i['NetworkAclId'])
    for j in i['Entries']:
        #print ("Protocol: "+j['Protocol']+" "+"RuleAction : "+j['RuleAction'])
        if j['Protocol'] == '-1' and j['RuleAction'] == 'allow':
            traffic_cnt += 1

#print (traffic_cnt)

if traffic_cnt > 0:
    high_cnt += 1
    print ("-"*75)
    print ("4.3 ACL 네트워크 인/아웃바운드 트래픽 정책 관리\t   중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 1개 이상의 Network ACL 인/아웃바운드 규칙에 대한 모든 트래픽이 \n       허용되어 있습니다.")
    print ("-"*75)
    print ("")

elif traffic_cnt == 0:
    print ("-"*75)
    print ("4.3 ACL 네트워크 인/아웃바운드 트래픽 정책 관리\t\t중요도 : " + Colors.RED + "상" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 Network ACL 인/아웃바운드 규칙에 대한 모든 트래픽이 허용되어 \n       있지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

any_cnt = 0

network_acl_rules = ec2_client.describe_route_tables()


for i in network_acl_rules['RouteTables']:
    #print ("RouteTableId : "+i['RouteTableId'])
    for j in i['Routes']:
        #print ("DestinationCidrBlock: "+j['DestinationCidrBlock']+" ")
        #print ("")
        if j['DestinationCidrBlock'] == '0.0.0.0/0':
            any_cnt += 1

#print (any_cnt)

if any_cnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("4.4 라우팅 테이블 정책 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 1개 이상의 목적지가 ANY로 설정되어 있습니다.")
    print ("-"*75)
    print ("")

elif any_cnt == 0:
    print ("-"*75)
    print ("4.4 라우팅 테이블 정책 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 목적지가 ANY 미설정 되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

Verify = True

igw = ec2_client.describe_internet_gateways()

instance = ec2_client.describe_instances()

try:
    for i in igw['InternetGateways']:
        if Verify == True:
            Verify_True_cnt = 0
            #print (i['InternetGatewayId'])
            for j in i['Attachments']:
                #print (j['VpcId'])
                #print("")
                for k in instance['Reservations']:
                    for l in k['Instances']:
                        #print(l['VpcId'])
                        if j['VpcId'] == l['VpcId']:
                            Verify = True
                            Verify_True_cnt += 1
                        else:
                            Verify = False



        elif Verify == False:
            low_cnt += 1
            print ("-"*75)
            print ("4.6 인터넷 게이트웨이 연결 관리\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
            print ("")
            print ("설명 : 다수의 인터넷 게이트웨이 관리 시 연결된 VPC내 인스턴스가 \n       존재하지 않습니다.")
            print ("-"*75)
            print ("")
            Verify_True_cnt = 0
            break

except KeyError:
    print ("종류된 인스턴스가 있습니다")

#print (Verify)
#print (Verify_True_cnt)

if Verify_True_cnt > 0:
    print ("-"*75)
    print ("4.6 인터넷 게이트웨이 연결 관리\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 다수의 인터넷 게이트웨이 관리 시 연결된 VPC내 인스턴스가 존재합니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

bucket = s3_client.list_buckets()

bucket_cnt = 0
acl_cnt = 0

for i in bucket['Buckets']:
    bucket_cnt += 1
    #print("")
    #print(i['Name'])
    try:
        List_public_access = s3_client.get_public_access_block(Bucket=i['Name'])
        for j in List_public_access['PublicAccessBlockConfiguration']:
            acl_cnt += 1
            #print (j[0:100])

    except s3_client.exceptions.ClientError:
        medium_cnt += 1
        print ("-"*75)
        print ("4.7 S3 버킷 접근 관리\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
        print ("")
        print ("설명 : 한개 이상의 버킷 권한에서 퍼블릭 액세스 차단이 해제되어 있습니다.")
        print ("-"*75)
        print ("")
        break

#print (bucket_cnt)
#print (acl_cnt)

acl_devide_cnt = int(acl_cnt/4)
#print (acl_devide_cnt)

if bucket_cnt == acl_devide_cnt:
    print ("-"*75)
    print ("4.7 S3 버킷 접근 관리\t\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 버킷의 퍼블릭 액세스 차단이 활성화되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

users = client.list_users()

user_iam_cnt = 0

groups_iam_cnt = 0

for key in users['Users']:
    #print("")
    #print (key['UserName'])
    List_of_Policies =  client.list_attached_user_policies(UserName=key['UserName'])
    for key in List_of_Policies['AttachedPolicies']:
        #print (key['PolicyName'])
        if key['PolicyName'] == 'AmazonRDSFullAccess' or key['PolicyName'] == 'AmazonRDSDirectoryServiceAccess' or key['PolicyName'] == 'AmazonRDSDataFullAccess' or key['PolicyName'] == 'AmazonRDSReadOnlyAccess' or key['PolicyName'] == 'AmazonRDSEnhancedMonitoringRole':
            user_iam_cnt += 1

for i in users['Users']:
    #print("")
    #print (i['UserName'])
    List_of_Groups =  client.list_groups_for_user(UserName=i['UserName'])
    for j in  List_of_Groups['Groups']:
        #print (j['GroupName'])
        List_of_GroupsPolicy =  client.list_attached_group_policies(GroupName=j['GroupName'])
        for k in List_of_GroupsPolicy['AttachedPolicies']:
            #print (k['PolicyName'])
            if k['PolicyName'] == 'AmazonRDSFullAccess' or k['PolicyName'] == 'AmazonRDSDirectoryServiceAccess' or k['PolicyName'] == 'AmazonRDSDataFullAccess' or k['PolicyName'] == 'AmazonRDSReadOnlyAccess' or k['PolicyName'] == 'AmazonRDSEnhancedMonitoringRole':
                groups_iam_cnt += 1

#print (user_iam_cnt)
#print (groups_iam_cnt)

if user_iam_cnt > 0 or groups_iam_cnt > 0:
    print ("-"*75)
    print ("4.8 RDS 리소스 액세스 권한 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : root 계정 관리자가 다수 사용자에게 RDS 리소스 생성 권한을 \n       설정했습니다.")
    print ("-"*75)
    print ("")

elif user_iam_cnt == 0 or groups_iam_cnt == 0:
    print ("-"*75)
    print ("4.8 RDS 리소스 액세스 권한 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : root 계정 관리자가 다수 사용자에게 RDS 리소스 생성 권한을 \n       설정하지 않았습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

users = client.list_users()

user_iam_cnt = 0

groups_iam_cnt = 0

for key in users['Users']:
    #print("")
    #print (key['UserName'])
    List_of_Policies =  client.list_attached_user_policies(UserName=key['UserName'])
    for key in List_of_Policies['AttachedPolicies']:
        #print (key['PolicyName'])
        if key['PolicyName'] == 'AmazonRDSFullAccess' or key['PolicyName'] == 'AmazonRDSDirectoryServiceAccess' or key['PolicyName'] == 'AmazonRDSDataFullAccess' or key['PolicyName'] == 'AmazonRDSReadOnlyAccess' or key['PolicyName'] == 'AmazonRDSEnhancedMonitoringRole':
            user_iam_cnt += 1

for i in users['Users']:
    #print("")
    #print (i['UserName'])
    List_of_Groups =  client.list_groups_for_user(UserName=i['UserName'])
    for j in  List_of_Groups['Groups']:
        #print (j['GroupName'])
        List_of_GroupsPolicy =  client.list_attached_group_policies(GroupName=j['GroupName'])
        for k in List_of_GroupsPolicy['AttachedPolicies']:
            #print (k['PolicyName'])
            if k['PolicyName'] == 'AmazonRDSFullAccess' or k['PolicyName'] == 'AmazonRDSDirectoryServiceAccess' or k['PolicyName'] == 'AmazonRDSDataFullAccess' or k['PolicyName'] == 'AmazonRDSReadOnlyAccess':
                groups_iam_cnt += 1

#print (user_iam_cnt)
#print (groups_iam_cnt)

if user_iam_cnt > 0 or groups_iam_cnt > 0:
    medium_cnt += 1
    print ("-"*75)
    print ("4.9 RDS API 작업 권한 관리 \t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 한 개 이상의 IAM 일반 사용자 권한에 RDS API 기능을 사용할 수 있는 \n       권한이 부여되어 있습니다.")
    print ("-"*75)
    print ("")

elif user_iam_cnt == 0 or groups_iam_cnt == 0:
    print ("-"*75)
    print ("4.9 RDS API 작업 권한 관리 \t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : IAM 일반 사용자 권한에 RDS API 기능을 사용할 수 있는 권한이 \n       부여되어 있지 않습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

rds_assoc_cnt = 0

rds_sub_cnt = 0

subents = ec2_client.describe_subnets()

rds_db_subnet_group = rds_client.describe_db_subnet_groups()

for key in subents['Subnets'] :
    for tag in key['Tags']:
        if tag['Key'] == 'Name':
            if tag['Value'].find('RDS') >= 0 or tag['Value'].find('rds') >= 0:
                #print(tag['Value'])
                #print(key['SubnetId'])
                #print("")
                for rds in rds_db_subnet_group['DBSubnetGroups']:
                    #print(rds['DBSubnetGroupName'])
                    for sub in rds['Subnets']:
                        #print(sub['SubnetIdentifier'])
                        if key['SubnetId'] == sub['SubnetIdentifier']:
                            rds_assoc_cnt += 1

for rds in rds_db_subnet_group['DBSubnetGroups']:
                    for sub in rds['Subnets']:
                        rds_sub_cnt += 1

#print(rds_sub_cnt)
#print(rds_assoc_cnt)

if rds_sub_cnt > rds_assoc_cnt:
    medium_cnt += 1
    print ("-"*75)
    print ("4.10 RDS 서브넷 가용 영역 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 가상 인스턴스와 RDS 연결 간의 불필요한 서브넷이 설정되어 있습니다.")
    print ("-"*75)
    print ("")

elif rds_sub_cnt == rds_assoc_cnt:
    print ("-"*75)
    print ("4.10 RDS 서브넷 가용 영역 관리\t\t\t   중요도 : " + Colors.DARKORANGE + "중" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 가상 인스턴스와 RDS 연결 간의 서브넷이 올바르게 설정되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

print ("")
print ('\033[1m' + "[5] 감사/추적 관리" + Colors.RESET)

ad_log_cnt = 0

cloudtrails = ct_client.describe_trails()

for i in cloudtrails['trailList']:
    try:
        #print (i['Name'])
        #print (i['S3BucketName'])
        #print (i['TrailARN'])
        #print (i['CloudWatchLogsLogGroupArn'])
        ad_log_cnt += 1
        if ad_log_cnt > 0:
            low_cnt += 1
            print ("-"*75)
            print ("5.1 AWS 사용자 계정 로깅 설정\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
            print ("")
            print ("설명 : 사용자 계정 로그 추적이 활성화 되어 있습니다.")
            print ("-"*75)
            print ("")
            break

    except KeyError:
        print ("-"*75)
        print ("5.1 AWS 사용자 계정 로깅 설정\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
        print ("")
        print ("설명 : 사용자 계정 로그 추적을 설정이 필요합니다.")
        print ("-"*75)
        print ("")
        break
    
#-------------------------------------------------------------------------------------------------------

str1 = 'aws-cloudtrail-logs'
ec2_log_cnt = 0

log_name = cw_client.describe_log_groups()
for i in log_name['logGroups']:
    #print (i['logGroupName']) 
    if i['logGroupName'].find(str1) == 0:
        ec2_log_cnt += 1

#print (ec2_log_cnt)

if ec2_log_cnt == 0:
    low_cnt += 1
    print ("-"*75)
    print ("5.2 가상 인스턴스 로깅 설정\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 가상 인스턴스 로그를 별도로 보관(물리적/논리적)하는 정책이 존재하고 있지 않습니다.")
    print ("-"*75)
    print ("")

elif ec2_log_cnt > 0:
    print ("-"*75)
    print ("5.2 가상 인스턴스 로깅 설정\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 가상 인스턴스 로그를 별도로 보관(물리적/논리적)하는 정책이 존재합니다.")
    print ("-"*75)
    print ("")


#-------------------------------------------------------------------------------------------------------

rds_instance = 0
rds_log_cnt = 0

rds_client = boto3.client('rds')
response = rds_client.describe_db_instances()
for db_instance in response['DBInstances']:
    #print("")
    #print (db_instance['DBInstanceIdentifier'])
    rds_instance += 1
    rds_log = rds_client.describe_db_log_files(DBInstanceIdentifier=db_instance['DBInstanceIdentifier'])
    for i in rds_log['DescribeDBLogFiles']:
        #print (i['LogFileName'])
        rds_log_cnt += 1
        break

#print (rds_instance)
#print (rds_log_cnt)

if rds_instance != rds_log_cnt:
    low_cnt += 1
    print ("-"*75)
    print ("5.3 RDS 로깅 설정\t\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : RDS 로그를 별도로 보관(물리적/논리적)하는 정책이 존재하고 있지 않습니다.")
    print ("-"*75)
    print ("")

elif rds_instance == rds_log_cnt:
    print ("-"*75)
    print ("5.3 RDS 로깅 설정\t\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : RDS 로그를 별도로 보관(물리적/논리적)하는 정책이 존재합니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------

bucket = s3_client.list_buckets()

public_access_cnt = 0 

for i in bucket['Buckets']:
    #print("")
    #print(i['Name'])
    List_public_access = s3_client.get_bucket_logging(Bucket=i['Name'])
    if 'LoggingEnabled' not in List_public_access:
        #print('server_public_access : False')
        public_access_cnt += 1

#print (public_access_cnt)
        
if public_access_cnt > 0:
    print ("-"*75)
    print ("5.4 S3 버킷 로깅 설정\t\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.RED + "취약" + Colors.RESET)
    print ("")
    print ("설명 : 한 개 이상이 S3 버킷이 서버 액세스 로킹 활성화가 되어 있지 않습니다.")
    print ("-"*75)
    print ("")

elif public_access_cnt == 0:
    print ("-"*75)
    print ("5.4 S3 버킷 로깅 설정\t\t\t\t   중요도 : " + Colors.GOLD + "하" + Colors.RESET + ", 결과 : " + Colors.LIGHTGREEN + "양호" + Colors.RESET)
    print ("")
    print ("설명 : 모든 S3 버킷이 서버 액세스 로킹 활성화가 되어 있습니다.")
    print ("-"*75)
    print ("")

#-------------------------------------------------------------------------------------------------------
total = 26

vulnerability = high_cnt + medium_cnt + low_cnt
good = total - vulnerability

print ("-"*75)
print ("총 26 / " + Colors.RED + "취약 " + str(vulnerability) + Colors.LIGHTGREEN + " / 양호 " + str(good) + Colors.RESET)
print (Colors.RED + "상 : " + str(high_cnt) + Colors.RESET) 
print (Colors.DARKORANGE + "중 : " + str(medium_cnt) + Colors.RESET)
print (Colors.GOLD + "하 : " + str(low_cnt) + Colors.RESET)
print ("-"*75)
#-------------------------------------------------------------------------------------------------------

sys.stdout.close()

s3_client.upload_file('AWS-check-report-' + timestr +'.txt', 'aws-check-result', 'AWS-check-report-' + timestr +'.txt') 

