{ Copyright (C) 2024 by Bill Stewart (bstewart at iname.com)

  This program is free software; you can redistribute it and/or modify it under
  the terms of the GNU Lesser General Public License as published by the Free
  Software Foundation; either version 3 of the License, or (at your option) any
  later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE. See the GNU General Lesser Public License for more
  details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program. If not, see https://www.gnu.org/licenses/.

}

{$MODE OBJFPC}
{$MODESWITCH UNICODESTRINGS}

unit utility;

interface

uses
  windows;

// DomainName output parameter will be an empty string if the computer is
// not a domain member; output parameter is not defined if function fails
function GetCurrentComputerDomain(out DomainName: string): DWORD;

function GetCurrentComputerName(out Name: string): DWORD;

function GetDCName(const DomainName: string; var DCName: string): DWORD;

function AccountLogon(const AuthorityName, AccountName: string;
  var Password: string): DWORD;

// Resets the password for an account to a random password, and optionally
// attempts a logon to the account. Parameters:
// AuthorityName: Computer or domain name where account is located
// AccountName: Username of the account
// PasswordLength: Length of the random password
// Delay: If Logon parameter = true, how many MS to wait before trying logon
// IsDomain: AuthorityName is domain name; use GetDCName to get DC name
// Logon: Attempt a LogonUserW using the account
// Result1: Error code for GetDCName/password reset
// Result2: Error code for LogonUserW (if Logon = true)
procedure ResetPasswordRandom(const AuthorityName, AccountName: string;
  const PasswordLength, Delay: Integer; const IsDomain, Logon: Boolean; 
  out Result1, Result2: DWORD);

function SameText(const S1, S2: string): Boolean;

implementation

const
  DS_RETURN_FLAT_NAME = $80000000;
  DS_WRITABLE_REQUIRED = $00001000;
  UF_LOCKOUT = $10;

type
  NET_API_STATUS = DWORD;

  DOMAIN_CONTROLLER_INFO = record
    DomainControllerName: LPWSTR;
    DomainControllerAddress: LPWSTR;
    DomainControllerAddressType: ULONG;
    DomainGuid: GUID;
    DomainName: LPWSTR;
    DnsForestName: LPWSTR;
    Flags: ULONG;
    DcSiteName: LPWSTR;
    ClientSiteName: LPWSTR;
  end;
  PDOMAIN_CONTROLLER_INFO = ^DOMAIN_CONTROLLER_INFO;

  NETSETUP_JOIN_STATUS = (
    NetSetupUnknownStatus = 0,
    NetSetupUnjoined = 1,
    NetSetupWorkgroupName = 2,
    NetSetupDomainName = 3);

  USER_INFO_1003 = record
    usri1003_password: LPWSTR;
  end;

function CryptBinaryToStringW(pbBinary: Pointer; cbBinary: DWORD;
  dwFlags: DWORD; pszString: LPWSTR; var pcchString: DWORD): BOOL;
  stdcall; external 'crypt32.dll';

function DsGetDcNameW(ComputerName, DomainName: LPCWSTR; DomainGuid: PGUID;
  SiteName: LPCWSTR; Flags: ULONG;
  var DomainControllerInfo: PDOMAIN_CONTROLLER_INFO): DWORD;
  stdcall; external 'netapi32.dll';

function NetApiBufferFree(Buffer: LPVOID): NET_API_STATUS;
  stdcall; external 'netapi32.dll';

function NetGetJoinInformation(lpServer: LPCWSTR; out lpNameBuffer: LPWSTR;
  out BufferType: NETSETUP_JOIN_STATUS): NET_API_STATUS; stdcall;
  external 'netapi32.dll';

function NetUserGetInfo(servername, username: LPCWSTR; level: DWORD;
  var bufptr: Pointer): NET_API_STATUS;
  stdcall; external 'netapi32.dll';

function NetUserSetInfo(servername, username: LPCWSTR; level: DWORD;
  buf: Pointer; parm_err: PDWORD): NET_API_STATUS;
  stdcall; external 'netapi32.dll';

function GetCurrentComputerDomain(out DomainName: string): DWORD;
var
  pName: PChar;
  JoinStatus: NETSETUP_JOIN_STATUS;
begin
  if NetGetJoinInformation(nil,       // LPCWSTR               lpServer
    pName,                            // LPWSTR                *lpNameBuffer
    JoinStatus) = ERROR_SUCCESS then  // PNETSETUP_JOIN_STATUS BufferType
  begin
    if JoinStatus = NetSetupDomainName then
      DomainName := string(pName)
    else
      DomainName := '';
    NetApiBufferFree(pName);  // LPVOID Buffer
    result := ERROR_SUCCESS;
  end
  else
    result := GetLastError();
end;

function GetCurrentComputerName(out Name: string): DWORD;
var
  NumChars: DWORD;
  pName: PChar;
begin
  NumChars := 0;
  GetComputerNameW(nil,  // LPWSTR  lpBuffer
    NumChars);           // LPDWORD nSize
  result := GetLastError();
  if result <> ERROR_BUFFER_OVERFLOW then
    exit;
  GetMem(pName, NumChars * SizeOf(Char));
  if GetComputerNameW(pName,  // LPWSTR  lpBuffer
    NumChars) then            // LPDWORD nSize
  begin
    Name := string(pName);
    if Name <> '' then
      Name := '\\' + Name;
    result := ERROR_SUCCESS;
  end
  else
    result := GetLastError();
  FreeMem(pName);
end;

function GetDCName(const DomainName: string; var DCName: string): DWORD;
var
  Flags: ULONG;
  pDCInfo: PDOMAIN_CONTROLLER_INFO;
begin
  Flags := DS_RETURN_FLAT_NAME or DS_WRITABLE_REQUIRED;
  result := DsGetDcNameW(nil,  // LPCWSTR                 ComputerName
    PChar(DomainName),         // LPCWSTR                 DomainName
    nil,                       // GUID                    DomainGuid
    nil,                       // LPCTSTR                 SiteName
    Flags,                     // ULONG                   Flags
    pDCInfo);                  // PDOMAIN_CONTROLLER_INFO DomainControllerInfo
  if result = ERROR_SUCCESS then
  begin
    DCName := string(pDCInfo^.DomainControllerName);
    NetApiBufferFree(pDCInfo);  // LPVOID Buffer
  end;
end;

function ResetAccountPassword(const ServerName, AccountName: string;
  var Password: string): DWORD;
var
  UserInfo1003: USER_INFO_1003;
begin
  {$IFDEF DEBUG}
  WriteLn('Attempting password reset for account "', AccountName,
    '" on server "', ServerName, '"');
  {$ENDIF}
  FillChar(UserInfo1003, SizeOf(UserInfo1003), 0);
  UserInfo1003.usri1003_password := PChar(Password);
  result := NetUserSetInfo(PChar(ServerName),  // LPCWSTR servername
    PChar(AccountName),                        // LPCWSTR username
    1003,                                      // DWORD   level
    @UserInfo1003,                             // LPBYTE  buf
    nil);                                      // LPDWORD parm_err
  {$IFDEF DEBUG}
  if result = ERROR_SUCCESS then
    WriteLn('Password reset succeeded')
  else
    WriteLn('Password reset FAILED');
  {$ENDIF}
end;

// Creates a buffer containing random bytes and then converts it to a
// base64-encoded string of the specified length
function GetRandomString(Len: Integer; var S: string): DWORD;
const
  BYTE_COUNT = 8192;
  CRYPT_STRING_BASE64 = $00000001;
  CRYPT_STRING_NOCRLF = $40000000;
var
  I: Integer;
  Bytes: array of Byte;
  Flags, NumChars: DWORD;
  Chars: array of Char;
begin
  if (Len <= 0) or (Len > BYTE_COUNT div SizeOf(Char)) then
  begin
    result := ERROR_INVALID_PARAMETER;
    exit;
  end;
  result := ERROR_INVALID_DATA;
  SetLength(Bytes, BYTE_COUNT);
  Randomize();
  for I := 0 to Length(Bytes) - 1 do
    Bytes[I] := Random(High(Byte) + 1);
  Flags := CRYPT_STRING_BASE64 or CRYPT_STRING_NOCRLF;
  if CryptBinaryToStringW(@Bytes[0],  // const BYTE *pbBinary
    Length(Bytes),                    // DWORD      cbBinary
    Flags,                            // DWORD      dwFlags
    nil,                              // LPWSTR     pszString
    NumChars) then                    // DWORD      pcchString
  begin
    SetLength(Chars, NumChars);
    if CryptBinaryToStringW(@Bytes[0],  // const BYTE *pbBinary
      Length(Bytes),                    // DWORD      cbBinary
      Flags,                            // DWORD      dwFlags
      @Chars[0],                        // LPWSTR     pszString
      NumChars) then                    // PDWORD     pcchString
    begin
      if Len > NumChars then
        Len := NumChars;
      SetLength(S, Len);
      Move(Chars[0], S[1], Len * SizeOf(Char));
      result := ERROR_SUCCESS;
    end;
    FillChar(Chars[0], Length(Chars) * SizeOf(Char), 0);
  end;
  FillChar(Bytes[0], Length(Bytes), 0);
end;

// Overwrites the specified string in memory
procedure WipeString(var S: string);
begin
  if S <> '' then
  begin
    FillChar(S[1], Length(S) * SizeOf(Char), 0);
  end;
end;

function AccountLogon(const AuthorityName, AccountName: string;
  var Password: string): DWORD;
var
  LogonHandle: HANDLE;
begin
  {$IFDEF DEBUG}
  WriteLn('Attempting logon to authority "', AuthorityName,
    '" using account "', AccountName, '"');
  {$ENDIF}
  if LogonUserW(PChar(AccountName),  // LPCWSTR lpszUsername
    PChar(AuthorityName),            // LPCWSTR lpszDomain
    PChar(Password),                 // LPCWSTR lpszPassword
    LOGON32_LOGON_NETWORK,           // DWORD   dwLogonType
    LOGON32_PROVIDER_DEFAULT,        // DWORD   dwLogonProvider
    LogonHandle) then                // PHANDLE phToken
  begin
    {$IFDEF DEBUG}
    WriteLn('Logon succeeded');
    {$ENDIF}
    CloseHandle(LogonHandle);  // HANDLE hObject
    result := ERROR_SUCCESS;
  end
  else
  begin
    result := GetLastError();
    {$IFDEF DEBUG}
    WriteLn('Logon FAILED');
    {$ENDIF}
  end;
end;

procedure ResetPasswordRandom(const AuthorityName, AccountName: string;
  const PasswordLength, Delay: Integer; const IsDomain, Logon: Boolean; 
  out Result1, Result2: DWORD);
var
  ServerName, RandomString: string;
begin
  if IsDomain then
  begin
    Result1 := GetDCName(AuthorityName, ServerName);
    if Result1 <> ERROR_SUCCESS then
      exit;
  end
  else
  begin
    Result1 := ERROR_SUCCESS;
    ServerName := AuthorityName;
  end;
  Result2 := ERROR_INVALID_DATA;
  Result1 := GetRandomString(PasswordLength, RandomString);
  if Result1 <> ERROR_SUCCESS then
    exit;
  Result2 := ERROR_SUCCESS;
  Result1 := ResetAccountPassword(ServerName, AccountName, RandomString);
  if (Result1 = ERROR_SUCCESS) and Logon then
  begin
    Sleep(Delay);
    Result2 := AccountLogon(AuthorityName, AccountName, RandomString);
  end;
  WipeString(RandomString);
end;

function SameText(const S1, S2: string): Boolean;
const
  CSTR_EQUAL = 2;
begin
  result := CompareStringW(GetThreadLocale(),  // LCID    Locale
    LINGUISTIC_IGNORECASE,                     // DWORD   dwCmpFlags
    PChar(S1),                                 // PCNZWCH lpString1
    -1,                                        // int     cchCount1
    PChar(S2),                                 // PCNZWCH lpString2
    -1) = CSTR_EQUAL;                          // int     cchCount2
end;

initialization

finalization

end.
