var net = require('net');
var readline = require('readline');
const { dialog } = require('electron').remote

console.log("renderer called");

var client = net.createConnection('/tmp/ebpfsnitch.sock');

let logger = document.getElementById('log');

function log(item) {
    logger.innerHTML += ("<p>" + item + "</p>");
}

var rl = readline.createInterface(client, client);

client.on("connect", function() {
    log("connected to unix socket");
});

rl.on("line", function(data) {
    log("got line " + data.toString());

    const event = JSON.parse(data.toString());
    
    let allow = false;
    
    let options  = {
        buttons: ["Allow", "Deny"],
        message: "Executable: " + event["executable"]
    }

    if (dialog.showMessageBoxSync(options) == 0) {
        allow = true;
    }

    const command = {
        executable: event["executable"],
        allow: allow
    }

    client.write(JSON.stringify(command) + "\n", function () {
        log("wrote response");
    })
});

client.on("close", function() {
    log("disconnected from unix socket");
});
client.on("close", function(err) {
    log("error with unix socket");
});