Java.perform(function () {
    const System = Java.use('java.lang.System');
    System.exit.implementation = function(status) {
        console.log(`[OK] System.exit(${status}) ignored`);
    };

    const Runtime = Java.use('java.lang.Runtime');
    Runtime.exit.implementation = function(status) {
        console.log(`[OK] Runtime.exit(${status}) ignored`);
    };

    Runtime.halt.implementation = function(status) {
        console.log(`[OK] Runtime.halt(${status}) ignored`);
    };

    const Process = Java.use('android.os.Process');
    Process.killProcess.implementation = function(pid) {
        console.log(`[OK] Process.killProcess(${pid}) ignored`);
        if (pid === Process.myPid()) {
            console.log('[!] Prevented killing of current process');
            return;
        }
        return this.killProcess(pid);
    };
    
    console.log("[!] Exit call hooks installed - System exit calls will be ignored");
});
