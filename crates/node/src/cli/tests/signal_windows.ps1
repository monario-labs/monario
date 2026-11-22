# Test-only, fixed code. Paths/mode are data from the owning Rust test process.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
public static class MonarioConsoleSignal {
    private delegate bool Handler(uint kind);
    private static readonly AutoResetEvent Delivered = new AutoResetEvent(false);
    private static readonly Handler Ignore = kind => {
        if (kind == 1) Delivered.Set();
        return true;
    };
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern uint GetConsoleProcessList([Out] uint[] ids, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool SetConsoleCtrlHandler(Handler handler, bool add);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GenerateConsoleCtrlEvent(uint kind, uint group);
    public static void AttachPrivate(int worker) {
        FreeConsole();
        if (!AttachConsole((uint)worker)) throw new Win32Exception();
        if (!SetConsoleCtrlHandler(Ignore, true)) throw new Win32Exception();
        var ids = new uint[16];
        uint count = GetConsoleProcessList(ids, (uint)ids.Length);
        uint self = (uint)Process.GetCurrentProcess().Id;
        if (count != 2 || !((ids[0] == self && ids[1] == worker) || (ids[1] == self && ids[0] == worker)))
            throw new InvalidOperationException("Console is not isolated to the owned worker and helper");
    }
    public static void SendBreak() {
        if (!GenerateConsoleCtrlEvent(1, 0)) throw new Win32Exception();
        // Broadcast includes this helper. FreeConsole resets its handlers;
        // acknowledge each notification before any detach can occur.
        if (!Delivered.WaitOne(5000)) throw new TimeoutException("Helper signal delivery timeout");
    }
    public static void Detach() { FreeConsole(); }
}
'@
$worker = $null
try {
    if ($env:MONAR_SIGNAL_MODE -notin @('graceful','burst','delayed-burst','error','crash','kill','conflict','probe','wrong-pid','exit-code')) { throw 'Invalid test mode' }
    $worker = Start-Process -FilePath $env:MONAR_SIGNAL_WORKER -ArgumentList @('--exact','cli::tests::signals::signal_worker','--nocapture') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $env:MONAR_SIGNAL_DIRECTORY 'worker.out') -RedirectStandardError (Join-Path $env:MONAR_SIGNAL_DIRECTORY 'worker.err')
    # Retain the process handle before signalling. Windows PowerShell otherwise
    # can lose ExitCode when the child dies before WaitForExit opens its handle.
    $null = $worker.Handle
    $readyPath = Join-Path $env:MONAR_SIGNAL_DIRECTORY 'ready.json'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $readyPath)) {
        $worker.Refresh()
        if ($worker.HasExited) {
            $code = $worker.ExitCode
            if ($null -eq $code) { throw 'Owned worker exit status unavailable' }
            exit $code
        }
        if ($timer.Elapsed.TotalSeconds -gt 40) { throw 'Owned worker readiness timeout' }
        Start-Sleep -Milliseconds 10
    }
    $ready = Get-Content -Raw -LiteralPath $readyPath | ConvertFrom-Json
    if ($ready.pid -ne $worker.Id) { throw 'Worker PID mismatch' }
    if ($env:MONAR_SIGNAL_MODE -eq 'kill') { $worker.Kill() }
    else {
        [MonarioConsoleSignal]::AttachPrivate($worker.Id)
        $count = if ($env:MONAR_SIGNAL_MODE -eq 'probe') { 128 } elseif ($env:MONAR_SIGNAL_MODE -in @('burst','delayed-burst')) { 4 } else { 1 }
        for ($i = 0; $i -lt $count; $i++) {
            if ($worker.HasExited) { throw 'Owned worker exited before signal burst completed' }
            [MonarioConsoleSignal]::SendBreak()
            if ($env:MONAR_SIGNAL_MODE -eq 'delayed-burst' -and $i -eq 0) { Start-Sleep -Seconds 5 }
            elseif ($env:MONAR_SIGNAL_MODE -eq 'burst') { Start-Sleep -Milliseconds 20 }
        }
        if ($env:MONAR_SIGNAL_MODE -eq 'exit-code') { Start-Sleep -Milliseconds 500 }
        if ($env:MONAR_SIGNAL_MODE -in @('probe','burst','delayed-burst')) { [IO.File]::WriteAllText((Join-Path $env:MONAR_SIGNAL_DIRECTORY 'sent'), 'sent') }
    }
    if (-not $worker.WaitForExit(20000)) { throw 'Owned worker shutdown timeout' }
    $code = $worker.ExitCode
    if ($null -eq $code) { throw 'Owned worker exit status unavailable' }
    exit $code
} finally {
    try {
        if ($null -ne $worker) {
            $worker.Refresh()
            if (-not $worker.HasExited) { $worker.Kill(); $worker.WaitForExit() }
            $worker.Dispose()
        }
    } finally { [MonarioConsoleSignal]::Detach() }
}
