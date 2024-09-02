var config = {
    package: 'com.your.apps', // Adjust this one
    printSummary: true,
    printDefinition: true,
    printArgs: true,
    printReturn: true,
    excludeStrings: [],
    timeout: 500
};

var colors = {
    reset: '\x1b[39;49;00m',
    black: '\x1b[30;01m',
    blue: '\x1b[34;01m',
    cyan: '\x1b[36;01m',
    gray: '\x1b[37;11m',
    green: '\x1b[32;11m',
    purple: '\x1b[35;11m',
    red: '\x1b[31;11m',
    yellow: '\x1b[33;11m',
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

function TraceMethods() {
    console.log();
    Java.enumerateLoadedClassesSync()
        .filter(c => c.includes(config.package))
        .forEach(c => {
            try {
                var classLogged = false;

                if (
                    config.excludeStrings.filter(e => c.toString().includes(e)).length
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
                        console.log(`${colors.light.blue}[INFO]${colors.reset} Class: ${c}`);
                        classLogged = true;
                    }

                    if (config.printSummary) {
                        console.log(`${colors.light.blue}[INFO]${colors.reset} Method: ${c}.${name}`);
                    }

                    var overloads = method.overloads;
                    for (var overload of overloads) {
                        overload.implementation = function () {
                            var callMessage = `Function: ${colors.light.green}${
                                config.printDefinition
                                    ? m
                                    : m.getDeclaringClass().getName() + '.' + name
                            }${colors.reset}`;

                            var argMessages = [];
                            if (config.printArgs) {
                                var i = 0;
                                for (var arg of arguments) {
                                    if (arg !== null && arg !== undefined) {
                                        argMessages.push(`Args[${i}]: ${colors.light.yellow}${arg.toString()}${colors.reset}`);
                                    }
                                    i++;
                                }
                            }

                            var ret = this[name].apply(this, arguments);

                            if (config.printReturn) {
                                var returnMessage = ret !== null && ret !== undefined
                                    ? ` [Return: ${colors.light.red}${ret.toString()}${colors.reset}]`
                                    : '';
                                if (argMessages.length > 0) {
                                    console.log(`${colors.light.blue}[INFO]${colors.reset} ${callMessage}${returnMessage} - ${argMessages.join(', ')}`);
                                } else {
                                    console.log(`${colors.light.blue}[INFO]${colors.reset} ${callMessage}${returnMessage}`);
                                }
                            }

                            return ret;
                        };
                    }
                });
            } catch (e) {
                console.log(`${colors.light.red}[ERROR]${colors.reset} ${e}`);
            }
        });
}

function HookMethods() {
    try {
        let CallMethod = Java.use("com.your.apps.MainActivity"); // Adjust this one
        CallMethod["func1"].implementation = function() {
            return false;
        };
        CallMethod["func2"].implementation = function() {
            return false;
        };
        // Add other function to hook here...
    } catch (e) {
        console.log(`${colors.light.red}[ERROR]${colors.reset} ${e}`);
    }
}

setTimeout(function () {
    Java.perform(function () {
        TraceMethods();
        HookMethods(); 
    });
}, config.timeout);
