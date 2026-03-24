unit hazar;

{$define hazar8}

interface

const
  S = {$ifdef hazar8}$00 {$endif}{$ifdef hazar16}$0000 {$endif};
  E = {$ifdef hazar8}$FF {$endif}{$ifdef hazar16}$FFFF {$endif};
  O = {$ifdef hazar8}$01 {$endif}{$ifdef hazar16}$0001 {$endif};
  R = {$ifdef hazar8}$07 {$endif}{$ifdef hazar16}$000F {$endif};
  N = {$ifdef hazar8}$100{$endif}{$ifdef hazar16}$10000{$endif};

type
  THazarInteger = {$ifdef hazar8}Byte{$endif}{$ifdef hazar16}Word{$endif};
  THazarData = array [S..E] of THazarInteger;
  THazarEncryption = class
  private
    FKeyLength: THazarInteger;
    FSBox, FMBox, FKey, FTKey: THazarData;
    procedure GenerateBox(var Box: THazarData);
  public
    constructor Initialize(Key: THazarData; KeyLength: THazarInteger);
    function GenerateKey: THazarData;
  end;

implementation

constructor THazarEncryption.Initialize(Key: THazarData; KeyLength: THazarInteger);
var
  I: Integer;
begin
  FKey := Key;
  FKeyLength := KeyLength;
  for I := S to E do
    FSBox[I] := I xor FKeyLength;
  GenerateBox(FSBox);
  FMBox := FSBox;
  GenerateBox(FMBox);
  GenerateKey;
end;

procedure THazarEncryption.GenerateBox(var Box: THazarData);
var
  I, J, A, B: Integer;
begin
  for I := S to E do
  begin
    FKey[I] := not (((Box[FKey[I]] and O) shl R) or (Box[FKey[I]] shr O));
    for J := S to E do
      Box[J] := ((Box[J] + (FKey[I])) mod N);
    FKey[((I + O) mod N)] := FKey[I] xor Box[FKey[((I + O) mod N)]];
    A := Box[FKey[I]];
    B := Box[FKey[((I + O) mod N)]];
    Box[FKey[I]] := B;
    Box[FKey[((I + O) mod N)]] := A;
  end;
end;

function THazarEncryption.GenerateKey: THazarData;
var
  I: Integer;
begin
  for I := S to E do
    FTKey[FMBox[((I + O) mod N)]] := FSBox[FMBox[(FKey[I] xor FKey[((I + O) mod N)])]];
  FKey := FTKey;
  Result := FKey;
end;

end.