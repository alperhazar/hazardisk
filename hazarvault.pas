unit hazarvault;

{
  HazarVault — Encrypted Virtual Disk Unit
  Uses THazarEncryption (hazar.pas) as keystream generator.

  Vault file layout:
  ┌──────────────────────────────────────────────────────────────────────────┐
  │   8 bytes  — Magic: "HAZARVLT" (plaintext)                               │
  ├──────────────────────────────────────────────────────────────────────────┤
  │ 256 bytes  — Verification block (keystream #1 stored verbatim)           │
  │              XOR with same keystream → all zeros confirms password       │
  ├──────────────────────────────────────────────────────────────────────────┤
  │ 256 bytes  — Encrypted vault metadata (keystream #2)                     │
  │              Version(2) + FileCount(4) + Reserved(250)                   │
  ├──────────────────────────────────────────────────────────────────────────┤
  │ 155648 B   — Encrypted file table: 512 × 304 bytes (607 blocks exactly)  │
  │              Each slot: Active(1) FileName(255) OrigSize(8)              │
  │              StoredSize(8) DataOffset(8) CreatedTime(8) ModifiedTime(8)  │
  │              Nonce(8)                                                    │
  ├──────────────────────────────────────────────────────────────────────────┤
  │  Variable  — Encrypted file payload (grows dynamically on add)           │
  │              Each file uses its own keystream: password key XOR nonce    │
  │              Nonce stored in table entry so compact needs no re-encrypt  │
  └──────────────────────────────────────────────────────────────────────────┘

  Total fixed header: 8 + 256 + 256 + 155648 = 156168 bytes

  Key design points:
    - Password verified before any operation.
    - File table and metadata are fully encrypted.
    - Per-file nonce means each file has an independent keystream.
    - Deletion triggers a compact rebuild: data is repacked, space reclaimed.
    - Encrypted file data is copied verbatim during compact (nonce travels
      with the entry so the keystream remains valid at any slot position).
}

interface

uses
  SysUtils, Classes, hazar;

const
  VAULT_VERSION    = 1;
  MAX_FILES        = 512;
  MAX_FILENAME_LEN = 255;
  BLOCK_SIZE       = 256;
  VERIFY_SIZE      = 256;
  META_SIZE        = 256;
  ENTRY_SIZE       = 304;                        { 1+255+8+8+8+8+8+8         }
  TABLE_SIZE       = MAX_FILES * ENTRY_SIZE;     { 512×304 = 155648 = 607 blocks }
  HEADER_SIZE      = 8 + VERIFY_SIZE + META_SIZE + TABLE_SIZE; { 156168      }

type
  { Packed so SizeOf = ENTRY_SIZE = 304 exactly. }
  TVaultEntry = packed record
    Active      : byte;
    FileName    : array [0 .. MAX_FILENAME_LEN - 1] of byte;
    OrigSize    : Int64;
    StoredSize  : Int64;    { always a multiple of BLOCK_SIZE }
    DataOffset  : Int64;    { absolute byte offset in vault file }
    CreatedTime : Int64;    { seconds since Delphi epoch (30-Dec-1899) }
    ModifiedTime: Int64;
    Nonce       : Int64;    { per-file random seed for keystream derivation }
  end;

  { Packed so SizeOf = META_SIZE = 256 exactly. }
  TVaultMeta = packed record
    Version   : Word;
    FileCount : LongWord;
    Reserved  : array [0 .. 249] of byte;
  end;

  TVaultTable = array [0 .. MAX_FILES - 1] of TVaultEntry;
  PVaultTable = ^TVaultTable;

  TVaultFileInfo = record
    FileName    : string;
    OrigSize    : Int64;
    CreatedTime : TDateTime;
    ModifiedTime: TDateTime;
  end;

  TVaultFileInfoArray = array of TVaultFileInfo;

{ Create a new, empty vault. Fails if the file already exists. }
function VaultCreate(const VaultFile, Password: string): boolean;

{ Add a file to the vault. Fails if vault is full or filename already exists. }
function VaultAdd(const VaultFile, Password, SourceFile: string): boolean;

{ Extract a file from the vault to DestFile.
  DestFile is the full destination path including filename. }
function VaultExtract(const VaultFile, Password, FileName, DestFile: string): boolean;

{ Delete a file from the vault and compact the container. }
function VaultDelete(const VaultFile, Password, FileName: string): boolean;

{ List all files stored in the vault. }
function VaultList(const VaultFile, Password: string; out Files: TVaultFileInfoArray): boolean;

{ Rename a file inside the vault. }
function VaultRename(const VaultFile, Password, OldName, NewName: string): boolean;

implementation

{ --------------------------------------------------------------------------- }
{ Internal constants                                                          }
{ --------------------------------------------------------------------------- }

const
  MAGIC: array [0 .. 7] of byte = (72, 65, 90, 65, 82, 86, 76, 84); { HAZARVLT }

{ --------------------------------------------------------------------------- }
{ Internal helpers                                                            }
{ --------------------------------------------------------------------------- }

procedure PasswordToKey(const Password: string; out Key: THazarData; out KLen: THazarInteger);
var
  I: integer;
begin
  FillChar(Key, SizeOf(Key), 0);
  if Length(Password) = 0 then
  begin
    KLen := 0;
    Exit;
  end;
  KLen := THazarInteger(Length(Password) mod N);
  for I := 1 to Length(Password) do
    Key[THazarInteger((I - 1) mod N)] :=
      Key[THazarInteger((I - 1) mod N)] xor THazarInteger(Ord(Password[I]));
end;

{ Derive a per-file key by XOR-ing the 8 nonce bytes into the base key.
  Because the nonce is stored in the table entry, this key can be reproduced
  at any time without knowing the file's slot index. }
procedure DeriveFileKey(const BaseKey: THazarData; Nonce: Int64; out FileKey: THazarData);
type
  TNonceBytes = array [0 .. 7] of byte;
var
  NB: TNonceBytes absolute Nonce;
  I : integer;
begin
  FileKey := BaseKey;
  for I := 0 to 7 do
    FileKey[THazarInteger(I)] := FileKey[THazarInteger(I)] xor NB[I];
end;

function GenerateNonce: Int64;
begin
  Result := Trunc(Now * 86400.0);
  Result := Result xor (Int64(Random($7FFFFFFF)) shl 17);
  Result := Result xor Int64(Random($7FFFFFFF));
end;

{ Filename is length-prefixed: byte[0] = length, byte[1..len] = chars.
  Max stored length is MAX_FILENAME_LEN - 1 = 254 characters. }
procedure SetEntryName(var Entry: TVaultEntry; const Name: string);
var
  Len: byte;
  I  : integer;
begin
  FillChar(Entry.FileName, MAX_FILENAME_LEN, 0);
  if Length(Name) = 0 then Exit;
  Len := byte(Length(Name));
  if Len > MAX_FILENAME_LEN - 1 then Len := MAX_FILENAME_LEN - 1;
  Entry.FileName[0] := Len;
  for I := 1 to Len do
    Entry.FileName[I] := byte(Ord(Name[I]));
end;

function GetEntryName(const Entry: TVaultEntry): string;
var
  Len: byte;
  I  : integer;
begin
  Len := Entry.FileName[0];
  if Len > MAX_FILENAME_LEN - 1 then Len := MAX_FILENAME_LEN - 1;
  SetLength(Result, Len);
  for I := 1 to Len do
    Result[I] := char(Entry.FileName[I]);
end;

function DateTimeToSec(DT: TDateTime): Int64;
begin
  Result := Trunc(DT * 86400.0);
end;

function SecToDateTime(Sec: Int64): TDateTime;
begin
  Result := Sec / 86400.0;
end;

{ XOR Buf (of BufSize bytes) with successive keystream blocks from Cipher.
  Used symmetrically for both encrypt and decrypt. }
procedure XORBuffer(Cipher: THazarEncryption; var Buf; BufSize: integer);
var
  P        : PByte;
  KeyStream: THazarData;
  I, Chunk : integer;
begin
  P := PByte(@Buf);
  while BufSize > 0 do
  begin
    if BufSize >= BLOCK_SIZE then Chunk := BLOCK_SIZE
    else Chunk := BufSize;
    KeyStream := Cipher.GenerateKey;
    for I := 0 to Chunk - 1 do
      P[I] := P[I] xor KeyStream[I];
    Inc(P, Chunk);
    Dec(BufSize, Chunk);
  end;
end;

{ --------------------------------------------------------------------------- }
{ Header read / write                                                         }
{ --------------------------------------------------------------------------- }

{ Read and decrypt vault header. Returns False on bad magic or wrong password. }
function ReadHeader(Stream: TFileStream; const Password: string;
                    out Meta: TVaultMeta; Table: PVaultTable): boolean;
var
  Hdr      : array [0 .. 7] of byte;
  Verify   : array [0 .. VERIFY_SIZE - 1] of byte;
  KeyStream: THazarData;
  Key      : THazarData;
  KLen     : THazarInteger;
  Cipher   : THazarEncryption;
  I        : integer;
  Valid    : boolean;
begin
  Result := False;
  Stream.Seek(0, soBeginning);
  if Stream.Read(Hdr, 8) < 8 then Exit;
  for I := 0 to 7 do
    if Hdr[I] <> MAGIC[I] then Exit;
  if Stream.Read(Verify, VERIFY_SIZE) < VERIFY_SIZE then Exit;
  PasswordToKey(Password, Key, KLen);
  Cipher := THazarEncryption.Initialize(Key, KLen);
  try
    KeyStream := Cipher.GenerateKey;
    Valid := True;
    for I := 0 to VERIFY_SIZE - 1 do
      if (Verify[I] xor KeyStream[I]) <> $00 then
      begin
        Valid := False;
        Break;
      end;
    if not Valid then Exit;
    FillChar(Meta, SizeOf(Meta), 0);
    if Stream.Read(Meta, META_SIZE) < META_SIZE then Exit;
    XORBuffer(Cipher, Meta, META_SIZE);
    FillChar(Table^, TABLE_SIZE, 0);
    if Stream.Read(Table^, TABLE_SIZE) < TABLE_SIZE then Exit;
    XORBuffer(Cipher, Table^, TABLE_SIZE);
    Result := True;
  finally
    Cipher.Free;
  end;
end;

{ Encrypt and write the full vault header starting at byte 0. }
procedure WriteHeader(Stream: TFileStream; const Password: string;
                      const Meta: TVaultMeta; Table: PVaultTable);
var
  Key      : THazarData;
  KLen     : THazarInteger;
  KeyStream: THazarData;
  Cipher   : THazarEncryption;
  EncMeta  : TVaultMeta;
  EncTable : PVaultTable;
begin
  New(EncTable);
  try
    Stream.Seek(0, soBeginning);
    Stream.WriteBuffer(MAGIC, 8);
    PasswordToKey(Password, Key, KLen);
    Cipher := THazarEncryption.Initialize(Key, KLen);
    try
      KeyStream := Cipher.GenerateKey;
      Stream.WriteBuffer(KeyStream, VERIFY_SIZE);
      EncMeta := Meta;
      XORBuffer(Cipher, EncMeta, META_SIZE);
      Stream.WriteBuffer(EncMeta, META_SIZE);
      EncTable^ := Table^;
      XORBuffer(Cipher, EncTable^, TABLE_SIZE);
      Stream.WriteBuffer(EncTable^, TABLE_SIZE);
    finally
      Cipher.Free;
    end;
  finally
    Dispose(EncTable);
  end;
end;

{ --------------------------------------------------------------------------- }
{ Public                                                                      }
{ --------------------------------------------------------------------------- }

function VaultCreate(const VaultFile, Password: string): boolean;
var
  Stream: TFileStream;
  Meta  : TVaultMeta;
  Table : PVaultTable;
begin
  Result := False;
  if FileExists(VaultFile) then Exit;
  New(Table);
  try
    FillChar(Meta, SizeOf(Meta), 0);
    Meta.Version := VAULT_VERSION;
    Meta.FileCount := 0;
    FillChar(Table^, TABLE_SIZE, 0);
    Stream := TFileStream.Create(VaultFile, fmCreate);
    try
      WriteHeader(Stream, Password, Meta, Table);
      Result := True;
    finally
      Stream.Free;
      if not Result then SysUtils.DeleteFile(VaultFile);
    end;
  finally
    Dispose(Table);
  end;
end;

function VaultAdd(const VaultFile, Password, SourceFile: string): boolean;
var
  Stream    : TFileStream;
  SrcStream : TFileStream;
  Meta      : TVaultMeta;
  Table     : PVaultTable;
  Key, FileKey, KeyStream: THazarData;
  KLen      : THazarInteger;
  Cipher    : THazarEncryption;
  Buffer    : array [0 .. BLOCK_SIZE - 1] of byte;
  EntryName : string;
  SlotIdx   : integer;
  I, BytesRead: integer;
begin
  Result := False;
  if not FileExists(VaultFile) then Exit;
  if not FileExists(SourceFile) then Exit;
  EntryName := ExtractFileName(SourceFile);
  if (Length(EntryName) = 0) or (Length(EntryName) > MAX_FILENAME_LEN - 1) then Exit;
  New(Table);
  try
    Stream := TFileStream.Create(VaultFile, fmOpenReadWrite or fmShareExclusive);
    try
      if not ReadHeader(Stream, Password, Meta, Table) then Exit;
      { Reject duplicate filenames }
      for I := 0 to MAX_FILES - 1 do
        if (Table^[I].Active = 1) and (GetEntryName(Table^[I]) = EntryName) then Exit;
      { Find a free slot }
      SlotIdx := -1;
      for I := 0 to MAX_FILES - 1 do
        if Table^[I].Active = 0 then
        begin
          SlotIdx := I;
          Break;
        end;
      if SlotIdx = -1 then Exit;  { Vault is full }
      Randomize;
      FillChar(Table^[SlotIdx], ENTRY_SIZE, 0);
      Table^[SlotIdx].Active := 1;
      SetEntryName(Table^[SlotIdx], EntryName);
      Table^[SlotIdx].DataOffset := Stream.Size;
      if Table^[SlotIdx].DataOffset < HEADER_SIZE then
        Table^[SlotIdx].DataOffset := HEADER_SIZE;
      Table^[SlotIdx].CreatedTime  := DateTimeToSec(Now);
      Table^[SlotIdx].ModifiedTime := Table^[SlotIdx].CreatedTime;
      Table^[SlotIdx].Nonce        := GenerateNonce;
      SrcStream := TFileStream.Create(SourceFile, fmOpenRead or fmShareDenyWrite);
      try
        Table^[SlotIdx].OrigSize   := SrcStream.Size;
        Table^[SlotIdx].StoredSize := 0;
        PasswordToKey(Password, Key, KLen);
        DeriveFileKey(Key, Table^[SlotIdx].Nonce, FileKey);
        Cipher := THazarEncryption.Initialize(FileKey, KLen);
        try
          Stream.Seek(Table^[SlotIdx].DataOffset, soBeginning);
          repeat
            FillChar(Buffer, BLOCK_SIZE, 0);
            BytesRead := SrcStream.Read(Buffer, BLOCK_SIZE);
            if BytesRead > 0 then
            begin
              KeyStream := Cipher.GenerateKey;
              for I := 0 to BLOCK_SIZE - 1 do
                Buffer[I] := Buffer[I] xor KeyStream[I];
              Stream.WriteBuffer(Buffer, BLOCK_SIZE);
              Inc(Table^[SlotIdx].StoredSize, BLOCK_SIZE);
            end;
          until BytesRead < BLOCK_SIZE;
        finally
          Cipher.Free;
        end;
      finally
        SrcStream.Free;
      end;
      Inc(Meta.FileCount);
      WriteHeader(Stream, Password, Meta, Table);
      Result := True;
    finally
      Stream.Free;
    end;
  finally
    Dispose(Table);
  end;
end;

function VaultExtract(const VaultFile, Password, FileName, DestFile: string): boolean;
var
  Stream    : TFileStream;
  DestStream: TFileStream;
  Meta      : TVaultMeta;
  Table     : PVaultTable;
  Key, FileKey, KeyStream: THazarData;
  KLen      : THazarInteger;
  Cipher    : THazarEncryption;
  Buffer    : array [0 .. BLOCK_SIZE - 1] of byte;
  EntryIdx  : integer;
  Remaining : Int64;
  I         : integer;
begin
  Result := False;
  if not FileExists(VaultFile) then Exit;
  New(Table);
  try
    Stream := TFileStream.Create(VaultFile, fmOpenRead or fmShareDenyWrite);
    try
      if not ReadHeader(Stream, Password, Meta, Table) then Exit;
      EntryIdx := -1;
      for I := 0 to MAX_FILES - 1 do
        if (Table^[I].Active = 1) and (GetEntryName(Table^[I]) = FileName) then
        begin
          EntryIdx := I;
          Break;
        end;
      if EntryIdx = -1 then Exit;
      PasswordToKey(Password, Key, KLen);
      DeriveFileKey(Key, Table^[EntryIdx].Nonce, FileKey);
      Cipher := THazarEncryption.Initialize(FileKey, KLen);
      try
        DestStream := TFileStream.Create(DestFile, fmCreate);
        try
          Stream.Seek(Table^[EntryIdx].DataOffset, soBeginning);
          Remaining := Table^[EntryIdx].StoredSize;
          while Remaining > 0 do
          begin
            if Stream.Read(Buffer, BLOCK_SIZE) < BLOCK_SIZE then Break;
            KeyStream := Cipher.GenerateKey;
            for I := 0 to BLOCK_SIZE - 1 do
              Buffer[I] := Buffer[I] xor KeyStream[I];
            DestStream.WriteBuffer(Buffer, BLOCK_SIZE);
            Dec(Remaining, BLOCK_SIZE);
          end;
          { Trim padding to restore exact original size }
          DestStream.Size := Table^[EntryIdx].OrigSize;
          Result := True;
        finally
          DestStream.Free;
          if not Result then SysUtils.DeleteFile(DestFile);
        end;
      finally
        Cipher.Free;
      end;
    finally
      Stream.Free;
    end;
  finally
    Dispose(Table);
  end;
end;

function VaultDelete(const VaultFile, Password, FileName: string): boolean;
var
  Stream    : TFileStream;
  TmpStream : TFileStream;
  TmpFile   : string;
  Meta      : TVaultMeta;
  Table     : PVaultTable;
  NewMeta   : TVaultMeta;
  NewTable  : PVaultTable;
  Buffer    : array [0 .. BLOCK_SIZE - 1] of byte;
  EntryIdx  : integer;
  SlotIdx   : integer;
  NewOffset : Int64;
  Remaining : Int64;
  BytesRead : integer;
  I         : integer;
begin
  Result := False;
  if not FileExists(VaultFile) then Exit;
  New(Table);
  New(NewTable);
  try
    Stream := TFileStream.Create(VaultFile, fmOpenReadWrite or fmShareExclusive);
    try
      if not ReadHeader(Stream, Password, Meta, Table) then Exit;
      EntryIdx := -1;
      for I := 0 to MAX_FILES - 1 do
        if (Table^[I].Active = 1) and (GetEntryName(Table^[I]) = FileName) then
        begin
          EntryIdx := I;
          Break;
        end;
      if EntryIdx = -1 then Exit;
      TmpFile := VaultFile + '.tmp';
      TmpStream := TFileStream.Create(TmpFile, fmCreate);
      try
        FillChar(NewMeta, SizeOf(NewMeta), 0);
        NewMeta.Version   := VAULT_VERSION;
        NewMeta.FileCount := 0;
        FillChar(NewTable^, TABLE_SIZE, 0);
        { Pre-write placeholder header to fill the first HEADER_SIZE bytes
          so that subsequent data seeks land beyond the header region. }
        WriteHeader(TmpStream, Password, NewMeta, NewTable);
        NewOffset := HEADER_SIZE;
        SlotIdx   := 0;
        for I := 0 to MAX_FILES - 1 do
        begin
          if (Table^[I].Active = 1) and (I <> EntryIdx) then
          begin
            NewTable^[SlotIdx]            := Table^[I];
            NewTable^[SlotIdx].DataOffset := NewOffset;
            { Copy encrypted payload verbatim — nonce in entry keeps it valid }
            Stream.Seek(Table^[I].DataOffset, soBeginning);
            TmpStream.Seek(NewOffset, soBeginning);
            Remaining := Table^[I].StoredSize;
            while Remaining > 0 do
            begin
              if Remaining >= BLOCK_SIZE then BytesRead := BLOCK_SIZE
              else BytesRead := integer(Remaining);
              BytesRead := Stream.Read(Buffer, BytesRead);
              if BytesRead <= 0 then Break;
              TmpStream.WriteBuffer(Buffer, BytesRead);
              Dec(Remaining, BytesRead);
            end;
            Inc(NewOffset, NewTable^[SlotIdx].StoredSize);
            Inc(SlotIdx);
            Inc(NewMeta.FileCount);
          end;
        end;
        { Overwrite placeholder with real header now that offsets are known }
        WriteHeader(TmpStream, Password, NewMeta, NewTable);
        Result := True;
      finally
        TmpStream.Free;
        if not Result then SysUtils.DeleteFile(TmpFile);
      end;
    finally
      Stream.Free;
    end;
    if Result then
    begin
      SysUtils.DeleteFile(VaultFile);
      Result := RenameFile(TmpFile, VaultFile);
      if not Result then SysUtils.DeleteFile(TmpFile);
    end;
  finally
    Dispose(Table);
    Dispose(NewTable);
  end;
end;

function VaultList(const VaultFile, Password: string; out Files: TVaultFileInfoArray): boolean;
var
  Stream: TFileStream;
  Meta  : TVaultMeta;
  Table : PVaultTable;
  I, J  : integer;
begin
  Result := False;
  Files  := nil;
  if not FileExists(VaultFile) then Exit;
  New(Table);
  try
    Stream := TFileStream.Create(VaultFile, fmOpenRead or fmShareDenyWrite);
    try
      if not ReadHeader(Stream, Password, Meta, Table) then Exit;
      SetLength(Files, Meta.FileCount);
      J := 0;
      for I := 0 to MAX_FILES - 1 do
        if Table^[I].Active = 1 then
        begin
          Files[J].FileName    := GetEntryName(Table^[I]);
          Files[J].OrigSize    := Table^[I].OrigSize;
          Files[J].CreatedTime := SecToDateTime(Table^[I].CreatedTime);
          Files[J].ModifiedTime:= SecToDateTime(Table^[I].ModifiedTime);
          Inc(J);
        end;
      Result := True;
    finally
      Stream.Free;
    end;
  finally
    Dispose(Table);
  end;
end;

function VaultRename(const VaultFile, Password, OldName, NewName: string): boolean;
var
  Stream  : TFileStream;
  Meta    : TVaultMeta;
  Table   : PVaultTable;
  EntryIdx: integer;
  I       : integer;
begin
  Result := False;
  if not FileExists(VaultFile) then Exit;
  if (Length(NewName) = 0) or (Length(NewName) > MAX_FILENAME_LEN - 1) then Exit;
  New(Table);
  try
    Stream := TFileStream.Create(VaultFile, fmOpenReadWrite or fmShareExclusive);
    try
      if not ReadHeader(Stream, Password, Meta, Table) then Exit;
      { Reject if new name already taken }
      for I := 0 to MAX_FILES - 1 do
        if (Table^[I].Active = 1) and (GetEntryName(Table^[I]) = NewName) then Exit;
      EntryIdx := -1;
      for I := 0 to MAX_FILES - 1 do
        if (Table^[I].Active = 1) and (GetEntryName(Table^[I]) = OldName) then
        begin
          EntryIdx := I;
          Break;
        end;
      if EntryIdx = -1 then Exit;
      SetEntryName(Table^[EntryIdx], NewName);
      Table^[EntryIdx].ModifiedTime := DateTimeToSec(Now);
      WriteHeader(Stream, Password, Meta, Table);
      Result := True;
    finally
      Stream.Free;
    end;
  finally
    Dispose(Table);
  end;
end;

end.
