program hazarvaultdemo;

{ =============================================================================
  HazarVaultDemo — Command-line tool for hazarvault.pas
  Usage:
    hazarvault create <vault> <password>
    hazarvault add    <vault> <password> <file>
    hazarvault extract <vault> <password> <filename> [dest_dir]
    hazarvault delete <vault> <password> <filename>
    hazarvault list   <vault> <password>
    hazarvault rename <vault> <password> <oldname> <newname>
  ============================================================================= }

{$APPTYPE CONSOLE}

uses
  SysUtils,
  hazar        in 'hazar.pas',
  hazarvault   in 'hazarvault.pas';

procedure PrintUsage;
begin
  WriteLn('HazarVault -- Encrypted Virtual Disk Tool');
  WriteLn('-----------------------------------------');
  WriteLn('Usage:');
  WriteLn;
  WriteLn('  hazarvault create <vault> <password>');
  WriteLn('      Create a new empty vault.');
  WriteLn;
  WriteLn('  hazarvault add <vault> <password> <file>');
  WriteLn('      Add a file to the vault.');
  WriteLn;
  WriteLn('  hazarvault extract <vault> <password> <filename> [dest_dir]');
  WriteLn('      Extract a file from the vault.');
  WriteLn('      dest_dir is optional; defaults to current directory.');
  WriteLn;
  WriteLn('  hazarvault delete <vault> <password> <filename>');
  WriteLn('      Delete a file and compact the vault.');
  WriteLn;
  WriteLn('  hazarvault list <vault> <password>');
  WriteLn('      List all files stored in the vault.');
  WriteLn;
  WriteLn('  hazarvault rename <vault> <password> <oldname> <newname>');
  WriteLn('      Rename a file inside the vault.');
  WriteLn;
  WriteLn('Exit codes:');
  WriteLn('  0  Success');
  WriteLn('  1  Bad arguments');
  WriteLn('  2  Operation failed');
end;

{ --------------------------------------------------------------------------- }

var
  Mode     : string;
  VaultFile: string;
  Password : string;
  OK       : boolean;
  Files    : TVaultFileInfoArray;
  DestFile : string;
  I        : integer;

begin
  if ParamCount < 3 then
  begin
    PrintUsage;
    Halt(1);
  end;

  Mode      := LowerCase(ParamStr(1));
  VaultFile := ParamStr(2);
  Password  := ParamStr(3);

  { ----------------------------------------------------------------------- }
  { create                                                                   }
  { ----------------------------------------------------------------------- }
  if Mode = 'create' then
  begin
    if ParamCount <> 3 then
    begin
      WriteLn('ERROR: create requires exactly 2 arguments.');
      WriteLn;
      PrintUsage;
      Halt(1);
    end;
    Write('Creating vault "', VaultFile, '" ... ');
    OK := VaultCreate(VaultFile, Password);
    if OK then WriteLn('OK')
    else
    begin
      WriteLn('FAILED  (file already exists or permission denied)');
      Halt(2);
    end;
  end

  { ----------------------------------------------------------------------- }
  { add                                                                      }
  { ----------------------------------------------------------------------- }
  else if Mode = 'add' then
  begin
    if ParamCount <> 4 then
    begin
      WriteLn('ERROR: add requires exactly 3 arguments.');
      WriteLn;
      PrintUsage;
      Halt(1);
    end;
    Write('Adding "', ParamStr(4), '" to "', VaultFile, '" ... ');
    OK := VaultAdd(VaultFile, Password, ParamStr(4));
    if OK then WriteLn('OK')
    else
    begin
      WriteLn('FAILED  (wrong password, source not found, duplicate name, or vault full)');
      Halt(2);
    end;
  end

  { ----------------------------------------------------------------------- }
  { extract                                                                  }
  { ----------------------------------------------------------------------- }
  else if Mode = 'extract' then
  begin
    if (ParamCount < 4) or (ParamCount > 5) then
    begin
      WriteLn('ERROR: extract requires 2 or 3 arguments.');
      WriteLn;
      PrintUsage;
      Halt(1);
    end;
    if ParamCount = 5 then
      DestFile := IncludeTrailingPathDelimiter(ParamStr(5)) + ParamStr(4)
    else
      DestFile := ParamStr(4);
    Write('Extracting "', ParamStr(4), '" from "', VaultFile, '" -> "', DestFile, '" ... ');
    OK := VaultExtract(VaultFile, Password, ParamStr(4), DestFile);
    if OK then WriteLn('OK')
    else
    begin
      WriteLn('FAILED  (wrong password, vault not found, or file not in vault)');
      Halt(2);
    end;
  end

  { ----------------------------------------------------------------------- }
  { delete                                                                   }
  { ----------------------------------------------------------------------- }
  else if Mode = 'delete' then
  begin
    if ParamCount <> 4 then
    begin
      WriteLn('ERROR: delete requires exactly 3 arguments.');
      WriteLn;
      PrintUsage;
      Halt(1);
    end;
    Write('Deleting "', ParamStr(4), '" from "', VaultFile, '" and compacting ... ');
    OK := VaultDelete(VaultFile, Password, ParamStr(4));
    if OK then WriteLn('OK')
    else
    begin
      WriteLn('FAILED  (wrong password, vault not found, or file not in vault)');
      Halt(2);
    end;
  end

  { ----------------------------------------------------------------------- }
  { list                                                                     }
  { ----------------------------------------------------------------------- }
  else if Mode = 'list' then
  begin
    if ParamCount <> 3 then
    begin
      WriteLn('ERROR: list requires exactly 2 arguments.');
      WriteLn;
      PrintUsage;
      Halt(1);
    end;
    OK := VaultList(VaultFile, Password, Files);
    if not OK then
    begin
      WriteLn('FAILED  (vault not found or wrong password)');
      Halt(2);
    end;
    if Length(Files) = 0 then
      WriteLn('Vault is empty.')
    else
    begin
      WriteLn(Format('%-40s %14s  %-19s  %-19s',
        ['Filename', 'Size (bytes)', 'Created', 'Modified']));
      WriteLn(StringOfChar('-', 98));
      for I := 0 to High(Files) do
        WriteLn(Format('%-40s %14d  %-19s  %-19s',
          [Files[I].FileName,
           Files[I].OrigSize,
           FormatDateTime('yyyy-mm-dd hh:nn:ss', Files[I].CreatedTime),
           FormatDateTime('yyyy-mm-dd hh:nn:ss', Files[I].ModifiedTime)]));
      WriteLn;
      WriteLn(Length(Files), ' file(s)  |  vault: ', VaultFile);
    end;
  end

  { ----------------------------------------------------------------------- }
  { rename                                                                   }
  { ----------------------------------------------------------------------- }
  else if Mode = 'rename' then
  begin
    if ParamCount <> 5 then
    begin
      WriteLn('ERROR: rename requires exactly 4 arguments.');
      WriteLn;
      PrintUsage;
      Halt(1);
    end;
    Write('Renaming "', ParamStr(4), '" -> "', ParamStr(5), '" in "', VaultFile, '" ... ');
    OK := VaultRename(VaultFile, Password, ParamStr(4), ParamStr(5));
    if OK then WriteLn('OK')
    else
    begin
      WriteLn('FAILED  (wrong password, file not found, or new name already taken)');
      Halt(2);
    end;
  end

  { ----------------------------------------------------------------------- }
  { Unknown                                                                  }
  { ----------------------------------------------------------------------- }
  else
  begin
    WriteLn('ERROR: Unknown command "', ParamStr(1), '".');
    WriteLn;
    PrintUsage;
    Halt(1);
  end;

end.
