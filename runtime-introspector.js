Java.perform(function () {
    const PREFIX = "com.example.something";
    const LOG_ARGS = true;
    const LOG_RET = false;

    function safeLog() {
        try {
            var args = Array.prototype.slice.call(arguments);
            console.log.apply(console, args);
        } catch (e) {}
    }

    function hookMethodsOf(className) {
        try {
            if (!className || className.indexOf(PREFIX) !== 0) return;
            safeLog("[TRACER] trying hook:", className);
            var Cls = Java.use(className);

            // Hook constructors
            try {
                if (Cls.$init) {
                    Cls.$init.overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            safeLog("[TRACER] " + className + ".<init>");
                            if (LOG_ARGS) {
                                try { safeLog("  args:", JSON.stringify(Array.prototype.slice.call(arguments))); } catch(e){}
                            }
                            // stack trace
                            try {
                                var ex = Java.use('java.lang.Exception').$new();
                                var st = Java.use('android.util.Log').getStackTraceString(ex);
                                safeLog("  stack:\\n" + st);
                            } catch (e) {}
                            var ret = ov.apply(this, arguments);
                            if (LOG_RET) safeLog("  ctor returned:", ret);
                            return ret;
                        }
                    });
                }
            } catch (e) {}

            try {
                var declMeths = Cls.class.getDeclaredMethods();
                for (var i = 0; i < declMeths.length; i++) {
                    try {
                        var m = declMeths[i];
                        var name = m.getName();
                        if (!name) continue;
                        if (name === "<init>" || name === "<clinit>") continue;
                        if (Cls[name]) {
                            Cls[name].overloads.forEach(function (ov) {
                                try {
                                    ov.implementation = function () {
                                        safeLog("[TRACER] " + className + "." + name + "()");
                                        if (LOG_ARGS) {
                                            try { safeLog("  args:", JSON.stringify(Array.prototype.slice.call(arguments))); } catch(e){}
                                        }
                                        try {
                                            var ex = Java.use('java.lang.Exception').$new();
                                            var st = Java.use('android.util.Log').getStackTraceString(ex);
                                            safeLog("  stack:\\n" + st);
                                        } catch (e) {}
                                        var ret = ov.apply(this, arguments);
                                        if (LOG_RET) {
                                            try { safeLog("  return:", JSON.stringify(ret)); } catch(e){}
                                        }
                                        return ret;
                                    };
                                } catch (e) {}
                            });
                        }
                    } catch (e) {}
                }
            } catch (e) {
                try {
                    Object.keys(Cls).filter(function (k) {
                        return typeof Cls[k] === 'function' && k !== '$class' && k !== '$init';
                    }).forEach(function (method) {
                        try {
                            Cls[method].overloads.forEach(function (ov) {
                                ov.implementation = function () {
                                    safeLog("[TRACER] " + className + "." + method);
                                    if (LOG_ARGS) {
                                        try { safeLog("  args:", JSON.stringify(Array.prototype.slice.call(arguments))); } catch(e){}
                                    }
                                    var ret = ov.apply(this, arguments);
                                    if (LOG_RET) {
                                        try { safeLog("  return:", JSON.stringify(ret)); } catch(e){}
                                    }
                                    return ret;
                                }
                            });
                        } catch (e) {}
                    });
                } catch (e) {}
            }

            safeLog("[TRACER] hooked:", className);
        } catch (e) {
            // ignore
            // safeLog("[TRACER] fail hook:", className, e);
        }
    }

    // Hook existing loaded classes
    try {
        var loaded = Java.enumerateLoadedClassesSync();
        loaded.forEach(function (c) {
            if (c.indexOf(PREFIX) === 0) {
                hookMethodsOf(c);
            }
        });
    } catch (e) {}

    // Also intercept future class loads by hooking ClassLoader.loadClass
    try {
        var CL = Java.use('java.lang.ClassLoader');
        CL.loadClass.overloads.forEach(function (ov) {
            ov.implementation = function (name) {
                var result = ov.apply(this, arguments);
                try {
                    if (name && name.indexOf(PREFIX) === 0) {
                        hookMethodsOf(name);
                    }
                } catch (e) {}
                return result;
            }
        });
        safeLog("[TRACER] hooked ClassLoader.loadClass to capture future loads");
    } catch (e) {}

    try {
        var Application = Java.use('android.app.Application');
        if (Application.onCreate) {
            Application.onCreate.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    safeLog("[TRACER] Application.onCreate()");
                    try {
                        var loaded2 = Java.enumerateLoadedClassesSync();
                        loaded2.forEach(function (c) {
                            if (c.indexOf(PREFIX) === 0) hookMethodsOf(c);
                        });
                    } catch (e) {}
                    return ov.apply(this, arguments);
                }
            });
        }
    } catch (e) {}

    safeLog("[TRACER] initialized for prefix:", PREFIX);
});
