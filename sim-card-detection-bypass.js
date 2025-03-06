Java.perform(function () {
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");

    TelephonyManager.getSimState.overload().implementation = function () {
        console.log("[+] Bypassing getSimState - Returning SIM_STATE_READY (5)");
        return 5;
    };

    TelephonyManager.getSubscriberId.overload().implementation = function () {
        console.log("[+] Bypassing getSubscriberId - Returning Fake Telkomsel IMSI");
        return "510100123456789";  // 51010 is the MCC-MNC for Telkomsel
    };

    TelephonyManager.getSimOperatorName.overload().implementation = function () {
        console.log("[+] Bypassing getSimOperatorName - Returning 'Telkomsel'");
        return "Telkomsel";
    };

    TelephonyManager.getSimSerialNumber.overload().implementation = function () {
        console.log("[+] Bypassing getSimSerialNumber - Returning Fake Serial");
        return "8962111123456789012";
    };

    TelephonyManager.getNetworkOperator.overload().implementation = function () {
        console.log("[+] Bypassing getNetworkOperator - Returning '51010'");
        return "51010";
    };

    TelephonyManager.getNetworkOperatorName.overload().implementation = function () {
        console.log("[+] Bypassing getNetworkOperatorName - Returning 'Telkomsel'");
        return "Telkomsel";
    };

    console.log("[+] Frida script for bypassing SIM Card checks (Telkomsel) loaded!");
});
