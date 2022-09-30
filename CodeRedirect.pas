{$WEAKPACKAGEUNIT ON}
unit CodeRedirect;

interface

uses
  System.SysUtils;

type
  TInstruction = class abstract
  const
    Default_OffSetLimit = 8192;
  public
    class function GetAddress(aIP: Pointer; aOffSet: NativeInt = 0): Pointer; overload;
    class function GetAddress(aIP: pointer; aSignature: array of byte; OffsetLimit:
        Integer = Default_OffSetLimit): Pointer; overload;
    class function GetAddressOfCall(aIP: pointer): Pointer; overload;
    class function GetAddressOfCall(aIP: pointer; aSignature: array of byte;
        OffsetLimit: Integer = Default_OffSetLimit): Pointer; overload;
    class procedure Patch(aAddr: Pointer; aPatchValues: array of Byte);
  end;

  TCodeRedirect = class(TObject)
  const
    Default_OffSetLimit = 8192;
  private
    FOriginalCode: TBytes;
    FSrcAddr: Pointer;
    FPatchCode: TBytes;
  public
    constructor CreateWithMethod(const aOldMethod, aNewMethod: Pointer); deprecated
        'Use https://github.com/MahdiSafsafi/DDetours';
    constructor Create(const aSrcAddr: Pointer; const aPatchCode: array of byte);
    procedure BeforeDestruction; override;
    procedure StopPatch;
    procedure StartPatch;
  end;

function IsRuntimePackaged: boolean;
function RuntimeArchitecture: TOSVersion.TArchitecture;

implementation

uses
  Winapi.Windows;

function IsRuntimePackaged: boolean;
begin
  Result := FindClassHInstance(TObject) <> MainInstance;
end;

function RuntimeArchitecture: TOSVersion.TArchitecture;
begin
  {$ifdef Win32}Exit(TOSVersion.TArchitecture.arIntelX86);{$endif}
  {$ifdef Win64}Exit(TOSVersion.TArchitecture.arIntelX64);{$endif}
  raise ENotSupportedException.Create('Platform not supported');
end;

class function TInstruction.GetAddress(aIP: Pointer; aOffSet: NativeInt = 0):
    Pointer;
type
  PAbsoluteIndirectJmp = ^TAbsoluteIndirectJmp;
  TAbsoluteIndirectJmp = packed record
    OpCode: Word;   //$FF25(Jmp, FF /4)
    Addr: Cardinal;
  end;

var J: PAbsoluteIndirectJmp;
{$ifdef Win32}
type
  PWin9xDebugThunk = ^TWin9xDebugThunk;
  TWin9xDebugThunk = packed record
    PUSH: Byte;
    Addr: Pointer;
    JMP: Byte;
    Offset: Integer;
  end;

  function IsWin9xDebugThunk(AAddr: Pointer): Boolean;
  begin
    Result := (AAddr <> nil) and
              (PWin9xDebugThunk(AAddr).PUSH = $68) and
              (PWin9xDebugThunk(AAddr).JMP = $E9);
  end;

begin
  if aIP = nil then Exit(aIP);

  if (Win32Platform <> VER_PLATFORM_WIN32_NT) and IsWin9xDebugThunk(aIP) then
    aIP := PWin9xDebugThunk(aIP).Addr;
  J := PAbsoluteIndirectJmp(aIP);
  if (J.OpCode = $25FF) then
    Result := PPointer(J.Addr)^
  else
    Result := aIP;
  Result := PByte(Result) + aOffset;
end;
{$endif}
{$ifdef Win64}
begin
  if aIP = nil then Exit(aIP);

  J := PAbsoluteIndirectJmp(aIP);
  if (J.OpCode = $25FF) then
    Result := PPointer(NativeUInt(aIP) + J.Addr + 6{Instruction Size})^
  else
    Result := aIP;

  Result := PByte(Result) + aOffset;
end;
{$endif}

class function TInstruction.GetAddress(aIP: pointer; aSignature: array of byte;
    OffsetLimit: Integer = Default_OffSetLimit): Pointer;
var P: ^NativeInt;
    i: integer;
    bFound: boolean;
begin
  i := 0;
  P := TInstruction.GetAddress(aIP);
  bFound := True;
  while not CompareMem(P, @aSignature, Length(aSignature)) do begin
    Inc(NativeUInt(P));
    Inc(i);
    if (i > OffsetLimit) then begin
      bFound := False;
      Break;
    end;
  end;
  if bFound then
    Result := P
  else
    Result := nil;
end;

class function TInstruction.GetAddressOfCall(aIP: pointer): Pointer;
var P: PByteArray;
begin
  P := aIP;
  if Assigned(P) then
    Result := Pointer(NativeInt(P) + 5{Instruction Size} + PInteger(@P[1])^)
  else
    Result := nil;
end;

class function TInstruction.GetAddressOfCall(aIP: pointer; aSignature: array of
    byte; OffsetLimit: Integer = Default_OffSetLimit): Pointer;
var P: PByteArray;
begin
  P := TInstruction.GetAddress(aIP, aSignature, OffsetLimit);
  if Assigned(P) then
    Result := Pointer(NativeInt(P) + 5{Instruction Size} + PInteger(@P[1])^)
  else
    Result := nil;
end;

class procedure TInstruction.Patch(aAddr: Pointer; aPatchValues: array of Byte);
var P: Cardinal;
    n: Integer;
begin
  n := Length(aPatchValues);
  if (n > 0) and VirtualProtect(aAddr, n, PAGE_EXECUTE_READWRITE, P) then begin
    Move(aPatchValues[0], aAddr^, n);
    VirtualProtect(aAddr, n, P, @P);
    FlushInstructionCache(GetCurrentProcess, aAddr, n);
  end;
end;

procedure TCodeRedirect.BeforeDestruction;
begin
  inherited;
  StopPatch;
end;

constructor TCodeRedirect.Create(const aSrcAddr: Pointer; const aPatchCode:
    array of byte);
begin
  inherited Create;
  FSrcAddr := aSrcAddr;

  SetLength(FPatchCode, Length(aPatchCode));
  Move(aPatchCode[0], FPatchCode[0], Length(aPatchCode));
  StartPatch;
end;

procedure TCodeRedirect.StopPatch;
var n: NativeUInt;
begin
  if not WriteProcessMemory(GetCurrentProcess, FSrcAddr, @FOriginalCode[0], Length(FOriginalCode), n) or (NativeInt(n) <> Length(FOriginalCode)) then
    RaiseLastOSError;
end;

constructor TCodeRedirect.CreateWithMethod(const aOldMethod, aNewMethod:
    Pointer);
var P: pointer;
    B: TBytes;
    O: PInteger;
begin
  if (aOldMethod = nil) or (aNewMethod = nil) then
    raise Exception.Create('Unknown method address');

  SetLength(B, 1{Jmp Instruction Size} + 4{Address size});
  P := TInstruction.GetAddress(aOldMethod);
  B[0] := $E9; // Jmp instruction
  O := @B[1];
  O^ := Integer(NativeInt(aNewMethod) - (NativeInt(P) + NativeInt(Length(B))));
  Create(P, B);
end;

procedure TCodeRedirect.StartPatch;
var OldProtect: Cardinal;
    n: Integer;
begin
  n := Length(FPatchCode);
  if VirtualProtect(FSrcAddr, n, PAGE_EXECUTE_READWRITE, OldProtect) then begin
    // Store original code
    SetLength(FOriginalCode, n);
    Move(FSrcAddr^, FOriginalCode[0], n);

    // Patch original code
    Move(FPatchCode[0], FSrcAddr^, n);

    VirtualProtect(FSrcAddr, n, OldProtect, @OldProtect);
    FlushInstructionCache(GetCurrentProcess, FSrcAddr, n);
  end;
end;

end.
