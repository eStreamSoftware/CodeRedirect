{$WEAKPACKAGEUNIT ON}
unit CodeRedirect;

interface

uses
  System.SysUtils;

type
  TNativeUInt = {$if CompilerVersion < 23}Cardinal{$else}NativeUInt{$ifend};
  TNativeInt = {$if CompilerVersion < 23}Integer{$else}NativeInt{$ifend};
  {$if CompilerVersion <= 21}PNativeUInt = PCardinal;{$ifend}

  TCodeRedirect = class(TObject)
  const
    Default_OffSetLimit = 8192;
  private
    FOriginalCode: TBytes;
    FSrcAddr: Pointer;
    FPatchCode: TBytes;
    class function GetActualAddr_Win(Proc: Pointer): Pointer;
  public
    constructor CreateWithMethod(const aOldMethod, aNewMethod: Pointer);
    constructor Create(const aSrcAddr: Pointer; const aPatchCode: array of byte);
    procedure BeforeDestruction; override;
    procedure StopPatch;
    procedure StartPatch;
    class function GetActualAddr(Proc: Pointer): Pointer;
    class function GetAddressOfInstruction(aMethodAddr: pointer; aSignature: array
        of byte; OffsetLimit: Integer = Default_OffSetLimit): Pointer;
    class function GetAddressOfMethodInMethod(aMethodAddr: pointer; aSignature:
        array of byte; OffsetLimit: Integer = Default_OffSetLimit): Pointer;
    class function IsRuntimePackaged: boolean;
  end;

implementation

uses
  Winapi.Windows;

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
var n: TNativeUInt;
begin
  if not WriteProcessMemory(GetCurrentProcess, FSrcAddr, @FOriginalCode[0], Length(FOriginalCode), n) or (TNativeInt(n) <> Length(FOriginalCode)) then
    RaiseLastOSError;
end;

constructor TCodeRedirect.CreateWithMethod(const aOldMethod, aNewMethod: Pointer);
var P: pointer;
    B: TBytes;
    O: PInteger;
begin
  if (aOldMethod = nil) or (aNewMethod = nil) then
    raise Exception.Create('Unknown method address');

  SetLength(B, 1{Jmp Instruction Size} + 4{Address size});
  P := GetActualAddr(aOldMethod);
  B[0] := $E9; // Jmp instruction
  O := @B[1];
  O^ := Integer(TNativeInt(aNewMethod) - (TNativeInt(P) + TNativeInt(Length(B))));
  Create(P, B);
end;

class function TCodeRedirect.GetActualAddr(Proc: Pointer): Pointer;
begin
  Result := nil;
  if Assigned(Proc) then
    Result := GetActualAddr_Win(Proc);
end;

class function TCodeRedirect.GetAddressOfInstruction(aMethodAddr: pointer;
    aSignature: array of byte; OffsetLimit: Integer = Default_OffSetLimit):
    Pointer;
var P: ^NativeInt;
    i: integer;
    bFound: boolean;
begin
  i := 0;
  P := TCodeRedirect.GetActualAddr(aMethodAddr);
  bFound := True;
  while not CompareMem(P, @aSignature, Length(aSignature)) do begin
    Inc(TNativeUInt(P));
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

class function TCodeRedirect.GetAddressOfMethodInMethod(aMethodAddr: pointer;
    aSignature: array of byte; OffsetLimit: Integer = Default_OffSetLimit):
    Pointer;
var P: PByteArray;
begin
  P := GetAddressOfInstruction(aMethodAddr, aSignature, OffsetLimit);
  if Assigned(P) then
    Result := Pointer(Integer(P) + 5{Instruction Size} + PInteger(@P[1])^)
  else
    Result := nil;
end;

class function TCodeRedirect.IsRuntimePackaged: boolean;
begin
  Result := FindClassHInstance(TObject) <> MainInstance;
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

class function TCodeRedirect.GetActualAddr_Win(Proc: Pointer): Pointer;
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
  if (Win32Platform <> VER_PLATFORM_WIN32_NT) and IsWin9xDebugThunk(Proc) then
    Proc := PWin9xDebugThunk(Proc).Addr;
  J := PAbsoluteIndirectJmp(Proc);
  if (J.OpCode = $25FF) then
    Result := PPointer(J.Addr)^
  else
    Result := Proc;
end;
{$endif}
{$ifdef Win64}
begin
  J := PAbsoluteIndirectJmp(Proc);
  if (J.OpCode = $25FF) then
    Result := PPointer(TNativeUInt(Proc) + J.Addr + 6{Instruction Size})^
  else
    Result := Proc;
end;
{$endif}

end.
