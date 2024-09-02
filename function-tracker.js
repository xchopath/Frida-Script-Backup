var config = {
    package: 'com.your.apps',
    printSummary: true,
    printDefinition: true,
    printArgs: true,
    printReturn: true,
    excludeStrings: [],
    timeout: 500
};

var levels = {
    info: 'INFO',
    warn: 'WARN',
    error: 'ERROR'
};

var colors = {
    reset: '\x1b[39;49;00m',
    black: '\x1b[30;01m',
    blue: '\x1b[34;01m',
    cyan: '\x1b[36;01m',
    gray: '\x1b[37;11m',
    green: '\x1b[32;01m',
    purple: '\x1b[35;01m',
    red: '\x1b[31;01m',
    yellow: '\x1b[33;01m',
    light: {
        black: '\x1b[30;11m',
        blue: '\x1b[34;11m',
        cyan: '\x1b[36;11m',
        gray: '\x1b[37;01m',
        green: '\x1b[32;11m',
        purple: '\x1b[35;11m',
        red: '\x1b[31;11m',
        yellow: '\x1b[33;11m'
    }
};

function log(level, text) {
    console.log(
        `${
            level === levels.info
                ? colors.light.blue
                : level === levels.warn
                ? colors.light.yellow
                : colors.light.red
        }[${level}]${colors.reset} ${text}`
    );
}

function tracePackage() {
    console.log();
    Java.enumerateLoadedClassesSync()
        .filter(c => c.includes(config.package))
        .forEach(c => {
            try {
                var classLogged = false;

                if (
                    config.excludeStrings.filter(e => c.toString().includes(e))
                        .length
                ) {
                    return;
                }

                var obj = Java.use(c);
                var methods = obj.class.getDeclaredMethods();
                methods.forEach(m => {
                    var name = m.getName();
                    var method = obj[name];
                    if (!method) {
                        return;
                    }

                    if (config.printSummary && !classLogged) {
                        log(levels.info, `Class: ${c}`);
                        classLogged = true;
                    }

                    if (config.printSummary) {
                        log(levels.info, `Method: ${c}.${name}`);
                    }

                    var overloads = method.overloads;
                    for (var overload of overloads) {
                        overload.implementation = function () {
                            var callMessage = `Function: ${
                                config.printDefinition
                                    ? m
                                    : m.getDeclaringClass().getName() + '.' + name
                            }`;

                            var argMessages = [];
                            if (config.printArgs) {
                                var i = 0;
                                for (var arg of arguments) {
                                    if (arg !== null && arg !== undefined) {
                                        argMessages.push(`Args[${i}]: ${arg.toString()}`);
                                    }
                                    i++;
                                }
                            }

                            var ret = this[name].apply(this, arguments);

                            if (config.printReturn) {
                                var returnMessage = ret !== null && ret !== undefined
                                    ? ` [Return: ${ret.toString()}]`
                                    : '';
                                if (argMessages != '') {
                                    log(levels.warn, `${callMessage}${returnMessage} - ${argMessages}`);
                                } else {
                                    log(levels.warn, `${callMessage}${returnMessage}`);
                                }
                            }

                            return ret;
                        };
                    }
                });
            } catch (e) {
                log(levels.error, e);
            }
        });
}

setTimeout(function () {
    Java.perform(function () {
        tracePackage();
    });
}, config.timeout);
