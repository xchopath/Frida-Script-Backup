'use strict';

setImmediate(function () {
    Java.perform(function () {

        const C = {
            RESET:   '\x1b[0m',
            BOLD:    '\x1b[1m',
            RED:     '\x1b[31m',
            GREEN:   '\x1b[32m',
            YELLOW:  '\x1b[33m',
            BLUE:    '\x1b[34m',
            MAGENTA: '\x1b[35m',
            CYAN:    '\x1b[36m',
            GRAY:    '\x1b[37m'
        };

        function logInfo(msg) {
            console.log(C.CYAN + '[*] ' + msg + C.RESET);
        }

        function logOk(msg) {
            console.log(C.GREEN + '[+] ' + msg + C.RESET);
        }

        function logWarn(msg) {
            console.log(C.YELLOW + '[!] ' + msg + C.RESET);
        }

        function logErr(msg) {
            console.log(C.RED + '[-] ' + msg + C.RESET);
        }

        function logSkip(msg) {
            console.log(C.GRAY + '[ ] ' + msg + C.RESET);
        }

        function logPatch(msg) {
            console.log(C.MAGENTA + '[*] ' + C.GREEN + msg + C.RESET);
        }

        const HOOK_STATS = { ok: 0, fail: 0 };

        function tryHook(desc, fn) {
            try {
                fn();
                logOk(desc);
                HOOK_STATS.ok++;
            } catch (e) {
                // logSkip(desc + ' (class not present / not used) :: ' + e);
                logSkip(desc + ' (class not found).');
                HOOK_STATS.fail++;
            }
        }

        let Thread = null;
        let JavaURL = null;
        const LAST_HOST_BY_THREAD = {};

        try {
            Thread = Java.use('java.lang.Thread');
        } catch (e) {
            logSkip('java.lang.Thread not available: ' + e);
        }

        try {
            JavaURL = Java.use('java.net.URL');
        } catch (e) {
            logSkip('java.net.URL not available, URL parsing will be basic: ' + e);
        }

        function setThreadHost(host) {
            if (!Thread || !host) return;
            try {
                const tid = Thread.currentThread().getId();
                LAST_HOST_BY_THREAD[tid] = String(host);
            } catch (e) {}
        }

        function getThreadHost() {
            if (!Thread) return null;
            try {
                const tid = Thread.currentThread().getId();
                return LAST_HOST_BY_THREAD[tid] || null;
            } catch (e) {
                return null;
            }
        }

        function extractHostCandidate(val) {
            if (val === null || val === undefined) return null;
            let s = String(val);
            if (!s) return null;

            if (JavaURL && s.indexOf('://') !== -1) {
                try {
                    const u = JavaURL.$new(s);
                    s = u.getHost();
                } catch (e) {
                }
            }

            if (s.length < 3 || s.indexOf(' ') !== -1) return null;

            return s;
        }

        function captureHostFromArgs(args) {
            if (!args) return null;
            for (let i = 0; i < args.length; i++) {
                const h = extractHostCandidate(args[i]);
                if (h) {
                    setThreadHost(h);
                    return h;
                }
            }
            return null;
        }

        function formatHostSuffix(host) {
            const h = host || getThreadHost();
            return ': ' + C.GRAY + (h || 'null');
        }

        console.log(C.BOLD + C.GREEN + '[i] Android SSL unpinning setup starting...' + C.RESET);

        // === Dynamic auto-patcher for SSLPeerUnverifiedException ===
        tryHook('SSLPeerUnverifiedException auto-patcher', function () {
            const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');

            UnverifiedCertError.$init.implementation = function (message) {
                logWarn('SSLPeerUnverifiedException thrown, trying dynamic patch...');

                try {
                    if (!Thread) {
                        logSkip('-- java.lang.Thread not available, cannot inspect stack trace');
                    } else {
                        const stackTrace = Thread.currentThread().getStackTrace();
                        var exceptionStackIndex = -1;

                        for (var i = 0; i < stackTrace.length; i++) {
                            if (stackTrace[i].getClassName() === 'javax.net.ssl.SSLPeerUnverifiedException') {
                                exceptionStackIndex = i;
                                break;
                            }
                        }

                        if (exceptionStackIndex === -1 || exceptionStackIndex + 1 >= stackTrace.length) {
                            logSkip('-- Could not locate calling frame in stack trace');
                        } else {
                            const callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                            const className = callingFunctionStack.getClassName();
                            const methodName = callingFunctionStack.getMethodName();

                            logInfo('-- Thrown by ' + className + '->' + methodName);

                            const callingClass = Java.use(className);
                            const target = callingClass[methodName];

                            if (!target) {
                                logSkip('-- Could not resolve calling method on class: ' + className + '->' + methodName);
                            } else {
                                const overloads = target.overloads || [];
                                var patched = 0;

                                for (var j = 0; j < overloads.length; j++) {
                                    const ov = overloads[j];

                                    if (ov.implementation) continue;

                                    var sig = 'java.lang.Object';
                                    if (ov.returnType && ov.returnType.className) {
                                        sig = ov.returnType.className;
                                    } else {
                                        try {
                                            sig = String(ov).split(' ')[0];
                                        } catch (e) {}
                                    }

                                    var kind = 'object';
                                    if (sig === 'void') {
                                        kind = 'void';
                                    } else if (sig === 'boolean') {
                                        kind = 'boolean';
                                    } else if (sig === 'int' || sig === 'short' || sig === 'byte' || sig === 'char' || sig === 'long') {
                                        kind = 'integer';
                                    } else if (sig === 'float' || sig === 'double') {
                                        kind = 'float';
                                    }

                                    ov.implementation = (function (sigLocal, kindLocal) {
                                        return function () {
                                            const host = captureHostFromArgs(arguments) || getThreadHost();
                                            logPatch(
                                                'Bypassing ' + className + '->' + methodName +
                                                ' [' + sigLocal + '] via SSLPeerUnverifiedException auto-patcher' +
                                                formatHostSuffix(host)
                                            );
                                            switch (kindLocal) {
                                                case 'void':
                                                    return;
                                                case 'boolean':
                                                    return true;
                                                case 'integer':
                                                    return 0;
                                                case 'float':
                                                    return 0.0;
                                                default:
                                                    return null;
                                            }
                                        };
                                    })(sig, kind);

                                    patched++;
                                }

                                if (patched > 0) {
                                    logOk('-- Patched ' + className + '->' + methodName + ' (' + patched + ' overload(s))');
                                } else {
                                    logSkip('-- No overloads patched (maybe already hooked or non-overloaded)');
                                }
                            }
                        }
                    }
                } catch (e) {
                    logErr('-- Failed to automatically patch caller: ' + e);
                }

                return this.$init(message);
            };
        });

        // === HttpsURLConnection hooks ===
        tryHook('HttpsURLConnection (hostname + socket factory)', function () {
            const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');

            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing HttpsURLConnection.setDefaultHostnameVerifier' + formatHostSuffix(host));
                return;
            };

            HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing HttpsURLConnection.setHostnameVerifier' + formatHostSuffix(host));
                return;
            };

            HttpsURLConnection.setSSLSocketFactory.implementation = function (sslSocketFactory) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing HttpsURLConnection.setSSLSocketFactory' + formatHostSuffix(host));
                return;
            };
        });

        // === SSLParameters: matikan hostname verification berbasis algorithm ===
        tryHook('SSLParameters.setEndpointIdentificationAlgorithm', function () {
            const SSLParameters = Java.use('javax.net.ssl.SSLParameters');
            SSLParameters.setEndpointIdentificationAlgorithm.implementation = function (algo) {
                const host = getThreadHost();
                logPatch('Bypassing SSLParameters.setEndpointIdentificationAlgorithm(' + algo + ')' + formatHostSuffix(host));
                return;
            };
        });

        // === SSLContext / global TrustManager (Android < 7 & generic) ===
        tryHook('SSLContext.init custom TrustManager', function () {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');

            const TrustManager = Java.registerClass({
                name: 'dev.asd.test.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });

            const TrustManagers = [TrustManager.$new()];

            const SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );

            SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing SSLContext.init, installing custom TrustManager (trust-all)' + formatHostSuffix(host));
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        });

        // ===== CONSCRYPT / PLATFORM TRUSTMANAGER =====
        tryHook('TrustManagerImpl (com.android.org.conscrypt)', function () {
            const array_list = Java.use('java.util.ArrayList');
            const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

            TrustManagerImpl.checkTrustedRecursive.implementation = function (a1, a2, a3, a4, a5, a6) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive' + formatHostSuffix(host));
                return array_list.$new();
            };

            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                const h = extractHostCandidate(host) || host;
                setThreadHost(h);
                logPatch('Bypassing com.android.org.conscrypt.TrustManagerImpl.verifyChain' + formatHostSuffix(h));
                return untrustedChain;
            };
        });

        tryHook('TrustManagerImpl (org.conscrypt)', function () {
            const array_list = Java.use('java.util.ArrayList');
            const TrustManagerImpl = Java.use('org.conscrypt.TrustManagerImpl');

            TrustManagerImpl.checkTrustedRecursive.implementation = function (a1, a2, a3, a4, a5, a6) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing org.conscrypt.TrustManagerImpl.checkTrustedRecursive' + formatHostSuffix(host));
                return array_list.$new();
            };

            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                const h = extractHostCandidate(host) || host;
                setThreadHost(h);
                logPatch('Bypassing org.conscrypt.TrustManagerImpl.verifyChain' + formatHostSuffix(h));
                return untrustedChain;
            };
        });

        // ===== OKHTTP 3 / 4 =====
        tryHook('OkHTTPv3/v4 CertificatePinner.check(list)', function () {
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing OkHTTPv3/v4 CertificatePinner.check(list)' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('OkHTTPv3 CertificatePinner.check(cert)', function () {
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing OkHTTPv3 CertificatePinner.check(cert)' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('OkHTTPv3 CertificatePinner.check(cert array)', function () {
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing OkHTTPv3 CertificatePinner.check(cert array)' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('OkHTTPv3 CertificatePinner.check$okhttp', function () {
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner['check$okhttp'].implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing OkHTTPv3 CertificatePinner.check$okhttp' + formatHostSuffix(host));
                return;
            };
        });

        // ===== TRUSTKIT =====
        tryHook('Trustkit OkHostnameVerifier(SSLSession)', function () {
            const OkHostnameVerifier = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Trustkit OkHostnameVerifier(SSLSession)' + formatHostSuffix(host));
                return true;
            };
        });

        tryHook('Trustkit OkHostnameVerifier(cert)', function () {
            const OkHostnameVerifier = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            OkHostnameVerifier.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Trustkit OkHostnameVerifier(cert)' + formatHostSuffix(host));
                return true;
            };
        });

        tryHook('Trustkit PinningTrustManager.checkServerTrusted', function () {
            const PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
            PinningTrustManager.checkServerTrusted.implementation = function () {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Trustkit PinningTrustManager.checkServerTrusted' + formatHostSuffix(host));
            };
        });

        // ===== APPCELERATOR TITANIUM =====
        tryHook('Appcelerator PinningTrustManager.checkServerTrusted', function () {
            const PTM = Java.use('appcelerator.https.PinningTrustManager');
            PTM.checkServerTrusted.implementation = function () {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Appcelerator PinningTrustManager.checkServerTrusted' + formatHostSuffix(host));
            };
        });

        // ===== OpenSSL Conscrypt =====
        tryHook('OpenSSLSocketImpl Conscrypt', function () {
            const OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing OpenSSLSocketImpl Conscrypt.verifyCertificateChain' + formatHostSuffix(host));
            };
        });

        tryHook('OpenSSLEngineSocketImpl Conscrypt', function () {
            const OpenSSLEngineSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
            OpenSSLEngineSocketImpl.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (a, b) {
                const host = extractHostCandidate(b) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing OpenSSLEngineSocketImpl Conscrypt.verifyCertificateChain' + formatHostSuffix(host));
            };
        });

        // ===== Apache Harmony =====
        tryHook('OpenSSLSocketImpl Apache Harmony', function () {
            const OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing OpenSSLSocketImpl Apache Harmony.verifyCertificateChain' + formatHostSuffix(host));
            };
        });

        // ===== PhoneGap sslCertificateChecker =====
        tryHook('PhoneGap sslCertificateChecker', function () {
            const Checker = Java.use('nl.xservices.plugins.sslCertificateChecker');
            Checker.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing PhoneGap sslCertificateChecker.execute' + formatHostSuffix(host));
                return true;
            };
        });

        // ===== IBM MobileFirst / WorkLight / Cordova / etc =====
        tryHook('IBM MobileFirst pinTrustedCertificatePublicKey(string)', function () {
            const WLClient = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing IBM MobileFirst pinTrustedCertificatePublicKey(String)' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('IBM MobileFirst pinTrustedCertificatePublicKey(string array)', function () {
            const WLClient = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing IBM MobileFirst pinTrustedCertificatePublicKey(String[])' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)', function () {
            const HostVerifier = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            HostVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning(SSLSocket)' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('IBM WorkLight HostNameVerifierWithCertificatePinning (cert)', function () {
            const HostVerifier = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            HostVerifier.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning(cert)' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('IBM WorkLight HostNameVerifierWithCertificatePinning (string,string)', function () {
            const HostVerifier = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            HostVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (a, b, c) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning(String,String[])' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)', function () {
            const HostVerifier = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            HostVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning(SSLSession)' + formatHostSuffix(host));
                return true;
            };
        });

        tryHook('Conscrypt CertPinManager', function () {
            const CertPinManager = Java.use('com.android.org.conscrypt.CertPinManager');
            CertPinManager.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Conscrypt CertPinManager.isChainValid' + formatHostSuffix(host));
                return true;
            };
        });

        tryHook('CWAC-Netsecurity CertPinManager', function () {
            const CertPinManager = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
            CertPinManager.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing CWAC-Netsecurity CertPinManager.isChainValid' + formatHostSuffix(host));
                return true;
            };
        });

        tryHook('Worklight Androidgap WLCertificatePinningPlugin', function () {
            const Plugin = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
            Plugin.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Worklight Androidgap WLCertificatePinningPlugin.execute' + formatHostSuffix(host));
                return true;
            };
        });

        // ===== Netty =====
        tryHook('Netty FingerprintTrustManagerFactory', function () {
            const FTMF = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
            FTMF.checkTrusted.implementation = function (type, chain) {
                const host = captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Netty FingerprintTrustManagerFactory.checkTrusted' + formatHostSuffix(host));
            };
        });

        // ===== Squareup (OkHttp 2.x style) =====
        tryHook('Squareup CertificatePinner (cert)', function () {
            const CP = Java.use('com.squareup.okhttp.CertificatePinner');
            CP.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Squareup CertificatePinner.check(cert)' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('Squareup CertificatePinner (list)', function () {
            const CP = Java.use('com.squareup.okhttp.CertificatePinner');
            CP.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Squareup CertificatePinner.check(list)' + formatHostSuffix(host));
                return;
            };
        });

        tryHook('Squareup OkHostnameVerifier (cert)', function () {
            const OHV = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            OHV.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Squareup OkHostnameVerifier(cert)' + formatHostSuffix(host));
                return true;
            };
        });

        tryHook('Squareup OkHostnameVerifier (SSLSession)', function () {
            const OHV = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            OHV.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                const host = extractHostCandidate(a) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Squareup OkHostnameVerifier(SSLSession)' + formatHostSuffix(host));
                return true;
            };
        });

        // ===== WebView / Cordova WebView =====
        tryHook('Android WebViewClient.onReceivedSslError (SslErrorHandler)', function () {
            const WVC = Java.use('android.webkit.WebViewClient');
            WVC.onReceivedSslError.overload(
                'android.webkit.WebView',
                'android.webkit.SslErrorHandler',
                'android.net.http.SslError'
            ).implementation = function (view, handler, error) {
                let host = null;
                try {
                    const url = error.getUrl();
                    host = extractHostCandidate(url) || captureHostFromArgs(arguments) || getThreadHost();
                    setThreadHost(host);
                } catch (e) {}
                logPatch('Bypassing Android WebViewClient.onReceivedSslError' + formatHostSuffix(host));
                handler.proceed();
            };
        });

        tryHook('Apache Cordova CordovaWebViewClient.onReceivedSslError', function () {
            const CWVC = Java.use('org.apache.cordova.CordovaWebViewClient');
            CWVC.onReceivedSslError.overload(
                'android.webkit.WebView',
                'android.webkit.SslErrorHandler',
                'android.net.http.SslError'
            ).implementation = function (view, handler, error) {
                let host = null;
                try {
                    const url = error.getUrl();
                    host = extractHostCandidate(url) || captureHostFromArgs(arguments) || getThreadHost();
                    setThreadHost(host);
                } catch (e) {}
                logPatch('Bypassing Apache Cordova WebViewClient.onReceivedSslError' + formatHostSuffix(host));
                handler.proceed();
            };
        });

        // ===== Boye AbstractVerifier =====
        tryHook('Boye AbstractVerifier.verify', function () {
            const Av = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
            Av.verify.implementation = function (hostParam, ssl) {
                const host = extractHostCandidate(hostParam) || captureHostFromArgs(arguments) || getThreadHost();
                logPatch('Bypassing Boye AbstractVerifier.verify' + formatHostSuffix(host));
            };
        });

        // DONE
        logInfo('Unpinning setup completed');
        logInfo('Hook summary: ' + HOOK_STATS.ok + ' hook(s) installed, ' + HOOK_STATS.fail + ' skipped (unused libs).');
        console.log(C.BOLD + C.GREEN + '[i] Android SSL unpinning ready!' + C.RESET);
    });
});
