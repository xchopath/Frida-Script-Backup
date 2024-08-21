Java.perform(function () {
    console.log("Listing loaded modules...");
    Process.enumerateModules({
        onMatch: function(module) {
            console.log(module.name + ": " + module.base.toString());
        },
        onComplete: function() {
            console.log("Finished listing modules.");
        }
    });
});
