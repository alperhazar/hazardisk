# HazarVault

A self-contained encrypted virtual disk implemented in Free Pascal / Lazarus, built on top of the original **Hazar** stream cipher algorithm.

HazarVault stores an arbitrary collection of files inside a single encrypted container file. The container grows dynamically as files are added, shrinks on deletion via a compact rebuild, and requires a password for every operation. No folders — all files live at the root of the vault.

---

## Table of Contents

- [Project Structure](#project-structure)
- [The Hazar Algorithm](#the-hazar-algorithm)
- [Vault File Format](#vault-file-format)
  - [Fixed Header](#fixed-header)
  - [Password Verification Block](#password-verification-block)
  - [Vault Metadata](#vault-metadata)
  - [File Table](#file-table)
  - [File Payload Area](#file-payload-area)
- [Security Design](#security-design)
  - [Password Key Derivation](#password-key-derivation)
  - [Per-File Nonce and Key Derivation](#per-file-nonce-and-key-derivation)
  - [Header Encryption](#header-encryption)
  - [File Encryption](#file-encryption)
  - [Compact on Delete](#compact-on-delete)
- [Building](#building)
- [Command-Line Tool](#command-line-tool)
  - [Commands](#commands)
  - [Exit Codes](#exit-codes)
  - [Examples](#examples)
- [API Reference](#api-reference)
- [Limits and Constraints](#limits-and-constraints)
- [File Size Reference](#file-size-reference)

---

## Project Structure

```
hazar.pas            Core algorithm — THazarEncryption key scheduler
hazarcipher.pas      In-memory stream cipher wrapper (THazarCipher)
hazario.pas          Standalone file encrypt / decrypt
hazardel.pas         Secure file deletion
hazarvault.pas       Encrypted virtual disk unit
hazarvaultdemo.pas   Command-line entry point
```

The vault depends only on `hazar.pas` and the FPC standard library. No external packages required.

---

## The Hazar Algorithm

`THazarEncryption` is an original key-scheduling and keystream-generation algorithm.

**Initialisation**

1. An S-Box is filled with `I xor KeyLength` for every index `I` in the range `[0..255]`.
2. `GenerateBox` is applied to the S-Box. Each iteration performs:
   - A bitwise rotation and `NOT` on the current key byte.
   - Full-array addition of the current key byte to every box element (mod 256).
   - XOR chaining between adjacent key entries via box lookups.
   - A swap of two box elements at key-derived positions.
3. The S-Box is copied to an M-Box, and `GenerateBox` is applied again — producing two independently derived permutation tables from a single key.

**Keystream generation**

Each call to `GenerateKey` produces a fresh 256-byte keystream block:

```
FTKey[ MBox[(I+1) mod 256] ] := SBox[ MBox[ Key[I] xor Key[(I+1) mod 256] ] ]
```

The internal key state is updated to the new table after each call, advancing the cipher. The algorithm never repeats a keystream block unless re-initialised with the same key.

**Compile-time width**

The algorithm supports two modes, selected at compile time in `hazar.pas`:

| Define | Type | Block | Range |
|---|---|---|---|
| `{$define hazar8}` | `Byte` | 256 bytes | 8-bit (default) |
| `{$define hazar16}` | `Word` | 65536 words | 16-bit |

HazarVault uses the default `hazar8` mode throughout.

---

## Vault File Format

### Fixed Header

The total fixed header is **156,168 bytes**, always present regardless of how many files are stored.

```
Offset       Size        Field
─────────────────────────────────────────────────────────────────────────────
0            8           Magic signature "HAZARVLT" (plaintext)
8            256         Password verification block (keystream #1, verbatim)
264          256         Encrypted vault metadata (keystream #2)
520          155,648     Encrypted file table: 512 × 304 bytes (keystream #3–609)
156,168      variable    Encrypted file payload (grows on add, shrinks on delete)
```

### Password Verification Block

The first `GenerateKey` output (256 bytes of raw keystream) is stored verbatim at offset 8. When opening a vault, the same keystream is reproduced and XOR'd against the stored block. If all 256 resulting bytes are `$00`, the password is correct. This check is performed before any other operation.

Storing the raw keystream is equivalent to encrypting 256 zero bytes, since `$00 XOR keystream = keystream`.

### Vault Metadata

256 bytes at offset 264, encrypted with keystream #2:

```pascal
TVaultMeta = packed record
  Version   : Word;       // 2 bytes — currently 1
  FileCount : LongWord;   // 4 bytes — number of active files
  Reserved  : array [0..249] of byte;  // 250 bytes — reserved for future use
end;
```

### File Table

155,648 bytes at offset 520, encrypted with keystreams #3 through #609 (607 consecutive 256-byte blocks). The table holds exactly 512 fixed-size slots of 304 bytes each:

```pascal
TVaultEntry = packed record
  Active       : byte;                           //   1 byte  — 1=used, 0=free
  FileName     : array [0..254] of byte;         // 255 bytes — length-prefixed
  OrigSize     : Int64;                          //   8 bytes — exact plaintext size
  StoredSize   : Int64;                          //   8 bytes — always multiple of 256
  DataOffset   : Int64;                          //   8 bytes — absolute offset in vault
  CreatedTime  : Int64;                          //   8 bytes — seconds since Delphi epoch
  ModifiedTime : Int64;                          //   8 bytes — seconds since Delphi epoch
  Nonce        : Int64;                          //   8 bytes — per-file random seed
end;
// Total: 1 + 255 + 8 + 8 + 8 + 8 + 8 + 8 = 304 bytes
```

**Filename encoding:** `FileName[0]` holds the length (0–254). `FileName[1..Len]` holds the ASCII bytes. The remainder is zeroed.

**Timestamps** are stored as whole seconds since the Delphi/FPC epoch (30 December 1899, 00:00:00) as `Int64`. This matches `Trunc(TDateTime * 86400)`.

### File Payload Area

Begins at offset 156,168. Files are appended sequentially. Each file's data is zero-padded to the next 256-byte boundary before encryption, so `StoredSize` is always a multiple of 256. The exact original size is preserved in `OrigSize` and used to trim padding on extraction.

---

## Security Design

### Password Key Derivation

The password string is folded into a `THazarData` (256-byte) key array:

- `KeyLength = Length(Password) mod 256`
- Each character `C` at position `I` is XOR'd into `Key[(I-1) mod 256]`

Passwords longer than 256 characters wrap around and keep accumulating. Empty passwords produce a zero key with `KeyLength = 0`.

### Per-File Nonce and Key Derivation

Each file receives a unique 8-byte nonce generated at add time:

```pascal
Nonce := Trunc(Now * 86400.0)
      xor (Int64(Random($7FFFFFFF)) shl 17)
      xor Int64(Random($7FFFFFFF));
```

The per-file encryption key is derived by XOR-ing the 8 nonce bytes into positions 0–7 of the base password key:

```
FileKey[I] := PasswordKey[I] xor NonceBytes[I]   for I in 0..7
```

This means every file in the vault is encrypted with a different keystream even if two files have identical contents. The nonce is stored inside the file table entry and is itself encrypted along with the rest of the table.

### Header Encryption

The verification block, metadata, and file table all share a single `THazarEncryption` instance initialised from the password key. They are encrypted with consecutive `GenerateKey` calls:

| Region | Keystream blocks used |
|---|---|
| Verification | #1 (256 bytes) |
| Metadata | #2 (256 bytes) |
| File table | #3 – #609 (607 × 256 = 155,648 bytes) |

Because the cipher is stateful, these regions are all interdependent — you cannot decrypt the file table without first advancing through blocks #1 and #2.

### File Encryption

Each file uses its own `THazarEncryption` instance initialised from the per-file derived key. Data is XOR'd with successive `GenerateKey` outputs in 256-byte blocks. The last block is zero-padded before encryption. On extraction, `OutStream.Size := OrigSize` removes the padding exactly.

### Compact on Delete

Deletion never leaves dead space. A full compact rebuild is performed:

1. A temporary `.tmp` file is created alongside the vault.
2. A placeholder header is written first so that subsequent data writes start at the correct offset (`HEADER_SIZE`).
3. All active entries except the deleted one are iterated. Their **encrypted payloads are copied verbatim** — no decryption or re-encryption occurs, because each file's nonce is embedded in its table entry and the per-file key is derived independently of the file's slot position.
4. Each entry's `DataOffset` is updated to reflect the new position.
5. The real header (with updated offsets) overwrites the placeholder.
6. The original vault is deleted and the `.tmp` file is renamed to take its place.

This approach means compact is safe even for large vaults — file data is never touched cryptographically during the operation.

---

## Building

Compile with Free Pascal Compiler directly:

```sh
fpc hazarvaultdemo.pas
```

Or open `hazarvaultdemo.pas` as the main program file in **Lazarus** and build normally.

**Requirements:**
- Free Pascal Compiler (FPC) 3.x or later
- Lazarus 3.x or later (optional, for IDE)
- No external libraries or packages

**All files must be in the same directory at compile time:**
```
hazar.pas
hazarvault.pas
hazarvaultdemo.pas
```

---

## Command-Line Tool

```
hazarvault <command> <vault> <password> [arguments]
```

### Commands

#### `create` — Create a new vault

```
hazarvault create <vault> <password>
```

Creates a new empty vault file. Fails if the file already exists. The fixed 156,168-byte header is written immediately, containing an empty encrypted file table.

---

#### `add` — Add a file to the vault

```
hazarvault add <vault> <password> <file>
```

Encrypts `<file>` and appends it to the vault. The filename stored inside the vault is the base name of `<file>` (path is stripped). Fails if:
- The vault is full (512 files)
- A file with the same name already exists in the vault
- The vault or source file cannot be opened

---

#### `extract` — Extract a file from the vault

```
hazarvault extract <vault> <password> <filename> [dest_dir]
```

Decrypts `<filename>` from the vault and writes it to disk. If `dest_dir` is provided, the file is written there; otherwise it is written to the current directory. The extracted file is trimmed to its exact original size. Fails without creating the destination file if the password is wrong or the filename is not found.

---

#### `delete` — Delete a file and compact the vault

```
hazarvault delete <vault> <password> <filename>
```

Removes `<filename>` from the vault and performs a full compact rebuild. The vault shrinks by the deleted file's stored size. The operation is atomic: a `.tmp` file is built and only replaces the original on success.

---

#### `list` — List all files in the vault

```
hazarvault list <vault> <password>
```

Prints a table of all files with filename, original size in bytes, creation timestamp, and last-modified timestamp. Example output:

```
Filename                                   Size (bytes)  Created              Modified
──────────────────────────────────────────────────────────────────────────────────────────────────
document.pdf                                     142580  2025-03-01 14:22:10  2025-03-01 14:22:10
photo.jpg                                       3842048  2025-03-10 09:05:44  2025-03-15 11:30:02
notes.txt                                          2048  2025-03-20 17:00:00  2025-03-21 08:15:33

3 file(s)  |  vault: myvault.hv
```

---

#### `rename` — Rename a file inside the vault

```
hazarvault rename <vault> <password> <oldname> <newname>
```

Renames a file entry in the vault. Only the file table is rewritten — no file data is touched. Updates the `ModifiedTime` of the renamed entry. Fails if `<newname>` is already taken.

---

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Bad arguments / unknown command |
| 2 | Operation failed (see console output for reason) |

---

### Examples

```sh
# Create a new vault
hazarvault create secrets.hv correcthorsebatterystaple

# Add files
hazarvault add secrets.hv correcthorsebatterystaple taxes_2024.pdf
hazarvault add secrets.hv correcthorsebatterystaple passport_scan.jpg
hazarvault add secrets.hv correcthorsebatterystaple notes.txt

# List contents
hazarvault list secrets.hv correcthorsebatterystaple

# Extract to current directory
hazarvault extract secrets.hv correcthorsebatterystaple notes.txt

# Extract to a specific directory
hazarvault extract secrets.hv correcthorsebatterystaple taxes_2024.pdf /home/user/documents

# Rename a file
hazarvault rename secrets.hv correcthorsebatterystaple notes.txt private_notes.txt

# Delete a file (vault is compacted automatically)
hazarvault delete secrets.hv correcthorsebatterystaple passport_scan.jpg

# Wrong password — no output file created, exit code 2
hazarvault extract secrets.hv wrongpassword notes.txt
```

---

## API Reference

All functions are in `hazarvault.pas` and return `boolean` — `True` on success, `False` on any failure.

```pascal
{ Create a new, empty vault. Fails if VaultFile already exists. }
function VaultCreate(const VaultFile, Password: string): boolean;

{ Encrypt SourceFile and append it to the vault.
  The stored name is ExtractFileName(SourceFile). }
function VaultAdd(const VaultFile, Password, SourceFile: string): boolean;

{ Decrypt FileName from the vault and write it to DestFile (full path). }
function VaultExtract(const VaultFile, Password, FileName, DestFile: string): boolean;

{ Remove FileName from the vault and compact. }
function VaultDelete(const VaultFile, Password, FileName: string): boolean;

{ Populate Files with info for every active entry. }
function VaultList(const VaultFile, Password: string;
                   out Files: TVaultFileInfoArray): boolean;

{ Rename OldName to NewName inside the vault. }
function VaultRename(const VaultFile, Password, OldName, NewName: string): boolean;
```

`TVaultFileInfo` returned by `VaultList`:

```pascal
TVaultFileInfo = record
  FileName    : string;
  OrigSize    : Int64;
  CreatedTime : TDateTime;
  ModifiedTime: TDateTime;
end;
```

---

## Limits and Constraints

| Parameter | Value |
|---|---|
| Maximum files per vault | 512 |
| Maximum filename length | 254 characters |
| Maximum file size | Limited only by disk space (`Int64` offset) |
| Supported OS | Any platform supported by FPC / Lazarus |
| Folder support | None — all files stored at root level |
| Concurrent access | Not supported — vault is opened exclusively for write operations |

---

## File Size Reference

| Region | Size |
|---|---|
| Magic signature | 8 bytes |
| Verification block | 256 bytes |
| Vault metadata | 256 bytes |
| File table (512 slots × 304 bytes) | 155,648 bytes |
| **Total fixed header** | **156,168 bytes** |
| Per-file overhead | StoredSize = ceil(OrigSize / 256) × 256 |

A vault containing only the fixed header (no files) is exactly **156,168 bytes**.

---

## License

This project is released as open source. See `LICENSE` for details.
