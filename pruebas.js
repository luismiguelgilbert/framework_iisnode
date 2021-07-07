var request = require('request');
var fs = require('fs');
var bodyParser = require('body-parser');
var httpntlm = require('httpntlm');                 //yarn add httpntlm

//var archivopdf = "https://localhost/ReportServerBI?/accVoucherOut_1&rs:ClearSession=true&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=1"
var archivopdf = "https://bitt.com.ec/ReportsBIServer?/accVoucherOut_1&rs:ClearSession=true&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=1"

console.log('pruebas')
console.log(archivopdf)

httpntlm.get({
    url: archivopdf,
    username: 'Administrador',
    password: 'Bitt2010',
    workstation: 'localhost',
    domain: '',
    binary: true,
    strictSSL: false,
    rejectUnauthorized: false
}, function (err, response){
    if(err){
	console.log("error");
	 console.log(err);
	 return err;
     }

fs.writeFile("file.pdf", response.body, function (err) {
        if(err) return console.log("error writing file");
        console.log("file.pdf saved!");
    });

//    console.log(res.headers);
//    console.log(res.body);
});

console.log('pruebas fin')