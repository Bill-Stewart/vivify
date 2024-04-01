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

program vivify;

{$MODE OBJFPC}
{$MODESWITCH UNICODESTRINGS}
{$R *.res}

uses
  windows,
  wargcv,
  wgetopts,
  WindowsMessages,
  utility;

const
  PROGRAM_NAME = 'vivify';
  PROGRAM_COPYRIGHT = 'Copyright (C) 2024 by Bill Stewart';
  DEFAULT_RANDOM_PASSWORD_LENGTH = 127;
  MAX_RANDOM_PASSWORD_LENGTH = 256;
  DEFAULT_DELAY_MSECS = 1000;
  MAX_DELAY_MSECS = 14400000;

type
  // Must specify exactly one action param,
  TActionParamGroup = (
    ActionParamHelp,
    ActionParamReset,
    ActionParamPassword);
  TActionParamSet = set of TActionParamGroup;
  // ...and 0 or 1 scope param
  TScopeParamGroup = (
    ScopeParamLocal,
    ScopeParamDomain);
  TScopeParamSet = set of TScopeParamGroup;

  TCommandLine = object
    ActionParamSet: TActionParamSet;
    ScopeParamSet: TScopeParamSet;
    Error: DWORD;
    ComputerName: string;
    DomainName: string;
    UserName: string;
    Password: string;
    Prompt: Boolean;
    Logon: Boolean;
    Quiet: Boolean;
    Delay: Integer;
    PasswordLength: Integer;
    function StrToInt(const S: string; const Max: Integer; out I: Integer): Boolean;
    procedure Parse();
  end;

function IntToStr(const I: Integer): string;
begin
  Str(I, result);
end;

function GetFileVersion(const FileName: string): string;
var
  VerInfoSize, Handle: DWORD;
  pBuffer: Pointer;
  pFileInfo: ^VS_FIXEDFILEINFO;
  Len: UINT;
begin
  result := '';
  VerInfoSize := GetFileVersionInfoSizeW(PChar(FileName),  // LPCWSTR lptstrFilename
    Handle);                                               // LPDWORD lpdwHandle
  if VerInfoSize > 0 then
  begin
    GetMem(pBuffer, VerInfoSize);
    if GetFileVersionInfoW(PChar(FileName),  // LPCWSTR lptstrFilename
      Handle,                                // DWORD   dwHandle
      VerInfoSize,                           // DWORD   dwLen
      pBuffer) then                          // LPVOID  lpData
    begin
      if VerQueryValueW(pBuffer,  // LPCVOID pBlock
        '\',                      // LPCWSTR lpSubBlock
        pFileInfo,                // LPVOID  *lplpBuffer
        Len) then                 // PUINT   puLen
      begin
        with pFileInfo^ do
        begin
          result := IntToStr(HiWord(dwFileVersionMS)) + '.' +
            IntToStr(LoWord(dwFileVersionMS)) + '.' +
            IntToStr(HiWord(dwFileVersionLS));
          // LoWord(dwFileVersionLS) intentionally omitted
        end;
      end;
    end;
    FreeMem(pBuffer);
  end;
end;

procedure Usage();
begin
  WriteLn(PROGRAM_NAME, ' ', GetFileVersion(ParamStr(0)), ' - ', PROGRAM_COPYRIGHT);
  WriteLn('This is free software and comes with ABSOLUTELY NO WARRANTY.');
  WriteLn();
  WriteLn('SYNOPSIS');
  WriteLn();
  WriteLn('Keeps an account active by securely resetting its password to a random password');
  WriteLn('and optionally performing a logon with the account.');
  WriteLn();
  WriteLn('USAGE');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' "<accountname>" [--domainname <name> | --localaccount]');
  WriteLn('[--passwordlength <length>] [--logon [--delay <msecs>]] [--noprompt] [--quiet]');
  WriteLn();
  WriteLn('PARAMETERS');
  WriteLn();
  WriteLn('* <accountname> - Specifies the account username - do not include a domain or');
  WriteLn('  computer name as a part of the username');
  WriteLn('* --domainname - Specifies the domain name where the account exists');
  WriteLn('* --localaccount - Specifies that the account is local (i.e., an account that');
  WriteLn('  exists only on the current computer)');
  WriteLn('* --passwordlength - Specifies random password length (0 to ', MAX_RANDOM_PASSWORD_LENGTH, ' characters)');
  WriteLn('* --logon - Attempts a logon using the account');
  WriteLn('* --delay - Waits at least this number of milliseconds after the password');
  WriteLn('  change before attempting a logon (0 to ', MAX_DELAY_MSECS, ' milliseconds)');
  WriteLn('* --noprompt - Do not prompt for confirmation');
  WriteLn('* --quiet - Suppresses output and error messages');
  WriteLn();
  WriteLn('REMARKS');
  WriteLn();
  WriteLn('* Default random password length is ', DEFAULT_RANDOM_PASSWORD_LENGTH, ' characters');
  WriteLn('* When using --logon, the default delay is ', DEFAULT_DELAY_MSECS, ' milliseconds; depending on the');
  WriteLn('  domain, a longer delay might be needed to account for Active Directory');
  WriteLn('  replication');
  WriteLn('* If the current computer is a domain member, the default value for');
  WriteLn('  --domainname is the current computer''s domain; otherwise, the account is');
  WriteLn('  assumed to be a local account (i.e., --localaccount)');
  WriteLn('* The --domainname parameter does not work if the current computer is not a');
  WriteLn('  domain member (i.e., the account name must specify a local account)');
  WriteLn('* The account running the program must have permission to reset the password');
  WriteLn('  for the named account.');
  WriteLn();
  WriteLn('EXIT CODE');
  WriteLn();
  WriteLn('The exit code will be 0 if the command completed successfully, or non-zero if');
  WriteLn('an error occurred.');
  WriteLn();
  WriteLn('DISCLAIMER');
  WriteLn();
  WriteLn('CAUTION! This program resets the password of an acccount to a random password');
  WriteLn('that is immediately cleared from memory. It is not possible to recover the');
  WriteLn('random password set on the account, so do not use this program on an account');
  WriteLn('that an application uses to authenticate (for example, to run a service or a');
  WriteLn('scheduled task): This will break the application the next time it uses the');
  WriteLn('acount to authenticate! You have been warned. The author of this program is not');
  WriteLn('responsible for broken applications as a result of this misuse of this program');
  WriteLn('(accidental or otherwise).');
end;

function TCommandLine.StrToInt(const S: string; const Max: Integer;
  out I: Integer): Boolean;
var
  Code: Word;
  N: Integer;
begin
  Val(S, N, Code);
  result := (Code = 0) and (N >= 0) and (N <= Max);
  if result then
    I := N;
end;

procedure TCommandLine.Parse();
var
  Opts: array[1..11] of TOption;
  Opt: Char;
  I: Integer;
begin
  with Opts[1] do
  begin
    Name := 'delay';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[2] do
  begin
    Name := 'domainname';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := 'd';
  end;
  with Opts[3] do
  begin
    Name := 'help';
    Has_arg := No_Argument;
    Flag := nil;
    value := 'h';
  end;
  with Opts[4] do
  begin
    Name := 'localaccount';
    Has_arg := No_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[5] do
  begin
    Name := 'noprompt';
    Has_arg := No_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[6] do
  begin
    Name := 'passwordlength';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[7] do
  begin
    Name := 'logon';
    Has_arg := No_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[8] do
  begin
    Name := 'password';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[9] do
  begin
    Name := 'quiet';
    Has_arg := No_Argument;
    Flag := nil;
    Value := 'q';
  end;
  with Opts[10] do
  begin
    Name := 'resetpassword';
    Has_arg := No_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[11] do
  begin
    Name := '';
    Has_arg := No_Argument;
    Flag := nil;
    Value := #0;
  end;
  ActionParamSet := [];
  ScopeParamSet := [];
  Error := ERROR_SUCCESS;
  Quiet := false;
  Logon := false;
  Prompt := true;
  ComputerName := '';
  DomainName := '';
  UserName := '';
  Password := '';
  Delay := DEFAULT_DELAY_MSECS;
  PasswordLength := DEFAULT_RANDOM_PASSWORD_LENGTH;
  OptErr := false;
  repeat
    Opt := GetLongOpts('d:hq', @Opts[1], I);
    case Opt of
      'd':
      begin
        DomainName := OptArg;
        Include(ScopeParamSet, ScopeParamDomain);
      end;
      'h':
      begin
        Include(ActionParamSet, ActionParamHelp);
        break;
      end;
      'q': Quiet := true;
      #0:
      begin
        case Opts[I].Name of
          'delay':
          begin
            if not StrToInt(OptArg, MAX_DELAY_MSECS, Delay) then
              Error := ERROR_INVALID_PARAMETER;
          end;
          'localaccount':
          begin
            Error := GetCurrentComputerName(ComputerName);
            if Error = ERROR_SUCCESS then
              Include(ScopeParamSet, ScopeParamLocal);
          end;
          'logon': Logon := true;
          'noprompt': Prompt := false;
          'passwordlength':
          begin
            if not StrToInt(OptArg, MAX_RANDOM_PASSWORD_LENGTH, PasswordLength) then
              Error := ERROR_INVALID_PARAMETER;
          end;
          'password':
          begin
            // --password is not documented as I don't recommend using it
            // except in a very restricted environment because the account
            // password is in plain-text on the command line
            Password := OptArg;
            Include(ActionParamSet, ActionParamPassword);
          end;
          'resetpassword':
          begin
            Include(ActionParamSet, ActionParamReset);
          end;
        end;
      end;
      '?':
      begin
        Error := ERROR_INVALID_PARAMETER;
        break;
      end;
    end;
  until Opt = EndOfOptions;
  if Error <> ERROR_SUCCESS then
    exit;
  UserName := ParamStr(OptInd);
  // Assume --resetpassword
  if PopCnt(DWORD(ActionParamSet)) = 0 then
    Include(ActionParamSet, ActionParamReset);
  // Parameter requirements:
  // * Username required
  // * Exactly 1 action param
  // * 0 or 1 scope param
  if (UserName = '') or (PopCnt(DWORD(ActionParamSet)) <> 1) or
    (PopCnt(DWORD(ScopeParamSet)) > 1) then
  begin
    Error := ERROR_INVALID_PARAMETER;
    exit;
  end;
  // If -d or --localaccount not specified:
  if PopCnt(DWORD(ScopeParamSet)) = 0 then
  begin
    Error := GetCurrentComputerDomain(DomainName);
    if Error <> ERROR_SUCCESS then
      exit;
    if DomainName <> '' then
    begin
      Include(ScopeParamSet, ScopeParamDomain);
    end
    else
    begin
      Error := GetCurrentComputerName(ComputerName);
      if Error = ERROR_SUCCESS then
        Include(ScopeParamSet, ScopeParamLocal);
    end;
  end;
end;

function Query(const Prompt: string): Boolean;
var
  Response: string;
begin
  repeat
    Write(Prompt);
    ReadLn(Response);
    result := SameText(Response, 'y') or SameText(Response, 'yes');
  until result or SameText(Response, 'n') or SameText(Response, 'no');
end;

var
  RC, LogonResult: DWORD;
  CmdLine: TCommandLine;
  AuthorityName: string;

begin
  RC := ERROR_SUCCESS;

  CmdLine.Parse();

  if (ParamCount = 0) or (ActionParamHelp in CmdLine.ActionParamSet) then
  begin
    Usage();
    exit;
  end;

  if CmdLine.Error <> ERROR_SUCCESS then
  begin
    RC := CmdLine.Error;
    if not CmdLine.Quiet then
      WriteLn(GetWindowsMessage(RC, true));
    ExitCode := Integer(RC);
    exit;
  end;

  if ScopeParamDomain in CmdLine.ScopeParamSet then
    AuthorityName := CmdLine.DomainName
  else
    AuthorityName := CmdLine.ComputerName;

  if ActionParamReset in CmdLine.ActionParamSet then
  begin
    if CmdLine.Prompt then
    begin
      if not Query('Set random password for account ''' + AuthorityName +
        '\' + CmdLine.UserName + '''? [Y/N] ') then
      begin
        RC := ERROR_CANCELLED;
        if not CmdLine.Quiet then
          WriteLn(GetWindowsMessage(RC, true));
      end;
    end;
    if RC = ERROR_SUCCESS then
    begin
      ResetPasswordRandom(AuthorityName, CmdLine.UserName,
        CmdLine.PasswordLength, CmdLine.Delay, ScopeParamDomain in
        CmdLine.ScopeParamSet, CmdLine.Logon, RC, LogonResult);
      if RC = ERROR_SUCCESS then
      begin
        if not CmdLine.Quiet then
          WriteLn('The password change completed successfully. (0)');
      end
      else
      begin
        if not CmdLine.Quiet then
          WriteLn('The password change failed. ', GetWindowsMessage(RC, true));
      end;
      if (RC = ERROR_SUCCESS) and CmdLine.Logon then
      begin
        if LogonResult = ERROR_SUCCESS then
        begin
          if not CmdLine.Quiet then
            WriteLn('The logon completed sucessfully. (0)');
        end
        else
        begin
          if not CmdLine.Quiet then
            WriteLn('The logon failed. ', GetWindowsMessage(LogonResult, true));
          RC := LogonResult;
        end;
      end;
    end;
  end
  else
  begin
    RC := AccountLogon(AuthorityName, CmdLine.UserName, CmdLine.Password);
    if not CmdLine.Quiet then
      WriteLn(GetWindowsMessage(RC, true));
  end;

  ExitCode := Integer(RC);
end.
