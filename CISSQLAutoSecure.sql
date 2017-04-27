
-- Script Created on 2/8/2017
-- Version 1.2 
-- CIS Full Security Auto Setup for SQL Server 2008 R2, 2012, 2014, 2016
--Do not Run This Script on SCCM Windows System Center SQL Servers (Require CLR and other specifics)
--Test carefully on any COTS running this e.g. PeopleSoft or Business Objects or DotNetNuke  SQL Servers databases (Require Mixed Mode)
--CIS cites DB mail as a security risk, but it is widely used in nearly every shop, comment the code out if needed
--Do not run this script on production environments without first testing in development

-- Find out the Version Details 

select @@servername as ServerName,
SERVERPROPERTY('ProductLevel') as ServicePack,
SERVERPROPERTY('ProductVersion') as BuildVersion,
SERVERPROPERTY('Edition') as Edition,
CONVERT(varchar(500),@@VERSION) as Version

-- Start MSSQL Server port check

print 'Start MSSQL Server port check'
DECLARE @portNumber varchar(20), @key varchar(100)
if charindex('\',@@servername,0) <>0
begin
set @key = 'SOFTWARE\MICROSOFT\Microsoft SQL Server\' +@@servicename+'\MSSQLServer\Supersocketnetlib\TCP'
end
else
begin
set @key = 'SOFTWARE\MICROSOFT\MSSQLServer\MSSQLServer\Supersocketnetlib\TCP'
end

EXEC master..xp_regread @rootkey='HKEY_LOCAL_MACHINE', @key=@key, @value_name='Tcpport', @value=@portNumber OUTPUT

SELECT 'Server Name: '+@@servername + ' Port Number:'+convert(varchar(10),@portNumber)
print 'End MSSQL Server port check'


-- End MSSQL Server port check

Print '– Note ::: Please ensure to configure SQL Server with a fixed customized port –'

Print '– Note ::: Apply latest Service Pack if applicable –'
--Checking the MSSQL Server Service account.
print ' '
print 'Start MSSQL Server Service Account check'
print ' '
SET NOCOUNT ON
GO
select "ServerName" = @@servername
go

declare @srvacct varchar(45), @instance varchar(45), @REGKEY varchar(128)

--For MSSQLServer service

select @instance=convert(varchar(45),SERVERPROPERTY('InstanceName'))
if (@instance is null) SET @instance = 'MSSQLSERVER' else SET @instance = 'MSSQL$'+@instance
SET @REGKEY = 'SYSTEM\CurrentControlSet\Services\'+@instance
execute master..xp_regread 'HKEY_LOCAL_MACHINE',@REGKEY,'ObjectName',@srvacct output
select (case @instance when null then 'SQLSERVERAGENT' else @instance end) as 'Service / Instance', @srvacct as 'Service account'


--For MSSQLServer agent

select @instance=convert(varchar(45),SERVERPROPERTY('InstanceName'))
if (@instance is null) SET @instance = 'SQLSERVERAGENT' else SET @instance = 'SQLAgent$'+@instance
SET @REGKEY = 'SYSTEM\CurrentControlSet\Services\'+@instance
execute master..xp_regread 'HKEY_LOCAL_MACHINE',@REGKEY,'ObjectName',@srvacct output
select (case @instance when null then 'MSSQLSERVER' else @instance end) as 'Service / Instance', @srvacct as 'Service account'
print ' '

print 'End MSSQL Server Service Account check'


print 'Start checking the groups added in SQL Server'
SELECT [name] as PrincipalName, type as PrincipalType, type_desc as TypeDescription, create_date as CreationDate,
modify_date as ModificationDate
FROM sys.server_principals
WHERE type_desc IN ('WINDOWS_GROUP')
ORDER BY type_desc
print '– End checking the groups added in SQL Server –'

print '– Start renaming sa to changed_sa –'

If  Exists (select loginname from master.dbo.syslogins 
    where name = 'sa' )
Begin ALTER LOGIN sa WITH NAME = changed_sa;
ALTER LOGIN changed_sa DISABLE;
End
print '– End renaming sa to changed_sa. changed_sa is now in DISABLED state –'


print '– Start setting Auditing to both failed and sucessful login attempts'
USE [master]
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', REG_DWORD, 3
GO
Print 'Auditing setup now completed'
print '– End setting Auditing to failed login attempts only –'
Print '– Start revoking execute permissions on SP to Public user –'

REVOKE EXECUTE ON xp_availablemedia TO PUBLIC;
REVOKE EXECUTE ON xp_enumgroups to PUBLIC;
REVOKE EXECUTE ON xp_fixeddrives TO PUBLIC;
REVOKE EXECUTE ON xp_dirtree TO PUBLIC; 
REVOKE EXECUTE ON xp_servicecontrol TO PUBLIC;
REVOKE EXECUTE ON xp_subdirs TO PUBLIC;
REVOKE EXECUTE ON xp_regaddmultistring TO PUBLIC;
REVOKE EXECUTE ON xp_regdeletekey TO PUBLIC;
REVOKE EXECUTE ON xp_regdeletevalue TO PUBLIC;
REVOKE EXECUTE ON xp_regenumvalues TO PUBLIC;
REVOKE EXECUTE ON xp_regremovemultistring TO PUBLIC;
REVOKE EXECUTE ON xp_regwrite TO PUBLIC;
REVOKE EXECUTE ON xp_regread TO PUBLIC;
Print 'Revoking permissions is now completed'
Print '– Revoking of execute permissions on SP to Public user is completed –'

Print ' '
Print 'Revoking CONNECT permissions on the guest user from these databases except master, msdb and tempdb'

DECLARE @database_id int, @database_name nvarchar(100);

DECLARE database_cursor CURSOR FOR
SELECT name
FROM [master].sys.databases
WHERE name NOT IN ('master', 'tempdb', 'msdb')
AND state = 0

OPEN database_cursor

FETCH NEXT FROM database_cursor
INTO @database_name

while (@@FETCH_STATUS <> -1)
BEGIN
Print @database_name
EXEC('USE [' + @database_name + '];'+

'REVOKE CONNECT FROM GUEST;'

);

FETCH NEXT FROM database_cursor
INTO @database_name
END

CLOSE database_cursor
DEALLOCATE database_cursor

Print 'Revoking CONNECT permissions on the guest user completed'

Print 'Disable Trustworthy Asset Start'


Declare @DBName varchar(100),@trust varchar(200),@guest varchar(200)
declare trustworthy cursor local fast_forward for
select name from sys.databases
where name not in ('Master','Model','MSDB','Tempdb')

open trustworthy
fetch next from trustworthy into @DBName ;
while @@FETCH_STATUS = 0
begin

Set @trust ='ALTER DATABASE ' + @DBName + ' SET trustworthy Off'

exec (@trust)

fetch next from trustworthy into @DBName;

end;
close trustworthy;
deallocate trustworthy;

Print 'Disable Trustworthy Asset completed'

Print '-Start setting up SQL Server Error Log Files to 15-'

USE master;
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', REG_DWORD, 15
GO

Print '-End : SQL Server Error Logs increased to 12-'
GO

--Verify whether password policy is enabled
-- a. Password expiration is set
-- b. Max failed login attempts
-- c. Alphanumeric password
-- d. Minmum password length

Print '-Start Password policy check-'

print 'MSSQL 2008 and above Password policy is enabled at windows level'
select name as Loginname,is_policy_checked, is_expiration_checked, is_disabled from master.sys.sql_logins
where is_policy_checked =1
--To enforce password policy
USE [master]
GO

DECLARE @user varchar(100)
DECLARE @policy varchar(100)

DECLARE user_cursor CURSOR FOR
select name from sys.sql_logins
where is_expiration_checked=0
and is_disabled=0
and name not in ('SA','changed_sa')
and type_desc='SQL_LOGIN'

OPEN user_cursor;
FETCH NEXT FROM user_cursor into @user;

WHILE @@FETCH_STATUS = 0
BEGIN
Set @policy = 'ALTER LOGIN ' + @user + ' WITH CHECK_EXPIRATION=ON, CHECK_POLICY=ON '

exec (@policy)

FETCH NEXT FROM user_cursor into @user;
END;

CLOSE user_cursor;
DEALLOCATE user_cursor;

Print ' '
Print '-End Password policy check-'

Print ' '
Print '-Start enabling/disabling server level configuration parameters-'

-- This part will disable Ad Hoc Distributed Queries Server Configuration Option —

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Ad Hoc Distributed Queries', 0;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;

--Disable CLR enabled 

EXECUTE sp_configure 'clr enabled', 0;
RECONFIGURE;

--Disable Cross DB ownership chaining —

EXECUTE sp_configure 'Cross db ownership chaining', 0;
RECONFIGURE;
GO

--Disable DB Mail —

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Database Mail XPs', 0;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;

--Disable Ole Automation Procedures —

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;

--Enable Remote Admin Connections

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Remote admin connections', 0;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;

--Disable scan for startup procedures —

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Scan for startup procs', 0;
RECONFIGURE;
GO

--Disable DAC
EXECUTE sp_configure 'Remote admin connections', 0;
RECONFIGURE;
GO

--Enable Default trace for audit purpose —

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Default trace enabled', 1;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;
--Disable xp_cmdshell —
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Xp_cmdshell', 0;
RECONFIGURE WITH OVERRIDE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;

Print '-End enabling/disabling server level configuration parameters-'


DECLARE @modeScriptOnly bit;
--set @modeScriptOnly = 1;	-- script all commands to results panel
set @modeScriptOnly = 0;	-- execute generated commands

USE master;

IF @modeScriptOnly = 1
	PRINT 'REVOKE VIEW ANY DATABASE FROM PUBLIC;';
ELSE
	REVOKE VIEW ANY DATABASE FROM PUBLIC;

DECLARE @database	varchar(100)
	,	@permission varchar(100)
	,	@schema		varchar(100)
	,	@sql		nvarchar(1000)
	,	@object		varchar(100)
	,	@role		varchar(100);

DECLARE csrDatabases CURSOR FAST_FORWARD FOR 
	SELECT name FROM sys.databases ORDER BY name;
	
OPEN csrDatabases;
FETCH NEXT FROM csrDatabases INTO @database;

WHILE (@@fetch_status = 0)
BEGIN
	SET @sql = 
		'DECLARE csrObjects CURSOR FAST_FORWARD FOR 
		SELECT p.permission_name, [schema] = SCHEMA_NAME(o.schema_id), object_name = o.name, role_name = u.name
		FROM [' + @database + '].sys.database_permissions p
		INNER JOIN [' + @database + '].sys.database_principals u ON p.grantee_principal_id = u.principal_id
		INNER JOIN [' + @database + '].sys.all_objects o ON o.object_id = p.major_id
		WHERE p.grantee_principal_id IN (0, 2) 
		ORDER BY u.name, o.schema_id, o.name, p.permission_name;';
	EXECUTE sp_executesql @sql;
	
	OPEN csrObjects;
	FETCH NEXT FROM csrObjects INTO @permission, @schema, @object, @role;
	
	WHILE (@@fetch_status = 0)
	BEGIN
		SELECT @sql = 'USE [' + @database + ']; REVOKE ' + @permission + ' ON [' + @schema + '].[' + @object + '] FROM ' + @role + ';';
		IF @modeScriptOnly = 1
			PRINT @sql;
		ELSE
			EXEC sp_executesql @sql;

		FETCH NEXT FROM csrObjects INTO @permission, @schema, @object, @role;
	END
	
	IF @database NOT IN ('master', 'tempdb')
	BEGIN
		SELECT @sql = 'USE [' + @database + ']; REVOKE CONNECT FROM GUEST;';
		IF @modeScriptOnly = 1
			PRINT @sql;
		ELSE
			EXEC sp_executesql @sql;
	END
	
	CLOSE csrObjects;
	DEALLOCATE csrObjects;

	FETCH NEXT FROM csrDatabases INTO @database;
END
CLOSE csrDatabases;
DEALLOCATE csrDatabases;
Print '-Guest Revokes Complete and Public View all databases!-'
EXEC sp_change_users_login @Action='Report'; 


Print 'Double checking all users for Orphans and fixing them if any are encountered'
DECLARE @UserCount INT
DECLARE @UserCurr INT
DECLARE @userName VARCHAR(100)
DECLARE @vsql NVARCHAR(4000)
DECLARE @Users TABLE(
id INT IDENTITY(1,1) PRIMARY KEY NOT NULL,
userName VARCHAR(100))
INSERT INTO @Users(UserName) 
SELECT [name] FROM 
master.[dbo].sysUsers 
SELECT @UserCount = max([id]) FROM @Users
SET @UserCurr = 1

WHILE (@UserCurr <= @UserCount)
BEGIN
 SELECT @userName=userName FROM @Users WHERE [id] =@UserCurr
 SET @vsql = '[dbo].[sp_change_users_login] ''AUTO_FIX'',''' + @userName + ''''
 -- EXEC(@vsql)
 PRINT @vsql
 SET @UserCurr = @UserCurr + 1
END

--Dropping built-in users role
PRINT 'Checking for BUILTIN\Administrators to Drop'

USE MASTER

IF EXISTS (SELECT * FROM sys.server_principals

WHERE name = N'BUILTIN\Administrators')

DROP LOGIN [BUILTIN\Administrators]

GO

--Enable Common Criteria - C2 is deprecated
EXEC sys.sp_configure N'show advanced options', N'1'  RECONFIGURE WITH OVERRIDE
GO
EXEC sys.sp_configure N'common criteria compliance enabled', N'1'
GO
RECONFIGURE WITH OVERRIDE
GO
EXEC sys.sp_configure N'show advanced options', N'0'  RECONFIGURE WITH OVERRIDE
GO
Print '-CIS Auto Benchmarker Complete!-'
