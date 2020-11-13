//process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';       //allows to get files from https even if certificate invalid
var fileUpload = require('express-fileupload')          //yarn add express-fileupload
var compression = require('compression')                //yarn add compression
var express = require('express');                       //yarn add express -- save
var sql = require('mssql');                             //yarn add mssql -- save
var jwt = require("jsonwebtoken");                      //yarn add jsonwebtoken --save
var request = require('request');                       //yarn add request --save
//var axios = require('axios');                         //yarn add axios --save
//var curl = require('curl');                           //yarn add curl --save
//var superagent = require('superagent');               //yarn add superagent --save
var WebSocket  = require("ws");                         //yarn add ws --save
var nodemailer = require("nodemailer");                 //yarn add nodemailer --save
var emlFormat = require("eml-format");                //yarn add eml-format --save
//var socketIO = require("socket.io");                  //yarn add socket.io --save
//var url = require('url');
//var http = require('http');
var https = require('https');
var app = express();
var fs = require('fs');
var bodyParser = require('body-parser');
var logToFile = function(message){ fs.appendFile(process.env.logPathFile, new Date().toISOString() + '\t' + message + '\r\n', (err) => { if (err) throw err; } ); }


logToFile('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
logToFile('API starting2...')
logToFile('Express Version: ' + require('express/package').version)
logToFile('Node Version: ' + process.version)
logToFile('Process ID: ' + process.pid)
logToFile('Running Path: ' + process.cwd())

//#region Public_Functions_&_Variables
app.use(compression())  //Enable Compression
app.use(fileUpload());  //Enable File Upload
app.use(bodyParser.json({limit: '50mb'}));  //Use bodyParser, and set file size
app.use(bodyParser.urlencoded({limit: '50mb', extended: true})); //Use bodyParser, and set file size
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");//Enabling CORS 
    res.header("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, contentType, Content-Type, Accept, Authorization");
    next();
});

var connectionPool = new sql.ConnectionPool(JSON.parse(process.env.dbConfig), (err, pool) => {
    if(err){
        logToFile('Error creating SQL connectionPool:' + err)
    }else{
        logToFile('SQL ConnectionPool Created with database: ' + pool.config.database)
    }
})

var veryfyToken = function(req, res, next){
    const bearerHeader = req.headers['authorization'];//get auth header value
    if(typeof bearerHeader !== 'undefined'){
        const bearer = bearerHeader.split(' '); //split by space
        const bearerToken = bearer[1]; //get token from array
        jwt.verify(bearerToken, process.env.secretEncryptionJWT, (jwtError, authData) => {
            if(jwtError){
                logToFile('Se produjo un error en la validación del token')
                logToFile(jwtError)
                res.status(403).send(jwtError);
            }else{
                if(req.body.sys_user_code || req.body.sys_user_code){
                    if( (authData.user.sys_user_code == req.query.sys_user_code) || (authData.user.sys_user_code == req.body.sys_user_code)    ){
                        req.token = bearerToken; //set the token
                        next();
                    }else{
                        logToFile('No coincide el código del usuario con el token')
                        logToFile(authData.user.sys_user_code)
                        logToFile(req.query.sys_user_code)
                        logToFile(req.body.sys_user_code)
                        res.status(403).send({message: 'No coincide el código del usuario con el token'});
                        return;
                    }
                }else{
                    req.token = bearerToken; //set the token
                    next();
                }
            }
        })
    }else{
        logToFile('No se pudo verificar token')
        res.status(403).send({message: 'No se pudo verificar token'});
    }
}

app.get(process.env.iisVirtualPath+'status', function (req, res) {
    //res.send(JSON.stringify(connectionPool));
    let respuesta = {
         status: 'UP'
        ,uptime: process.uptime()
        ,nodeVersion: process.version
        ,pid: process.pid
        ,platform: process.platform
        ,runningPath: process.cwd()
        ,memoryUsage: process.memoryUsage()
        ,resourceUsage: process.resourceUsage()
        ,connectionPool_eventsCount: connectionPool._eventsCount
        ,connectionPool_db: connectionPool.config.database
        ,connectionPool_connected: connectionPool._connected
        ,connectionPool_poolMax: connectionPool.pool.max
        ,connectionPool_poolUsed: connectionPool.pool.used
        
    }
    res.send(JSON.stringify(respuesta));
    //res.send(JSON.stringify(connectionPool));
});
//#endregion Public_Functions_


//#region Version_1_0_0

//#region SESSION_OTHERS
app.post(process.env.iisVirtualPath+'spSysLogin', function (req, res) {
    let start = new Date()
    logToFile('!!! New Login attempt from ' + 'Usuario: ' + req.body.sys_user_id + ' (' + req.ip + ')')
    new sql.Request(connectionPool)
    .input('sys_user_id', sql.VarChar(250), req.body.sys_user_id )
    .input('sys_user_password', sql.VarChar(100), req.body.sys_user_password )
    .execute('spSysLogin', (err, result) => {
        logToFile("Request:  " + req.originalUrl)
        logToFile("Perf spSysLogin:  " + ((new Date() - start) / 1000) + ' secs' )
        if(err){
            if(err&&err.originalError&&err.originalError.info){
                logToFile('DB Error: ' + JSON.stringify(err.originalError.info))
            }else{
                logToFile('DB Error: ' + JSON.stringify(err.originalError))
            }
            res.status(400).send(err.originalError);
            return;
        }
        if(result.recordset.length > 0){
            const user = {
                 username: req.body.sys_user_id
                ,sys_user_code: result.recordset[0].sys_user_code
                ,sys_profile_id: result.recordset[0].sys_profile_id
            }
            jwt.sign({user: user}, process.env.secretEncryptionJWT, (err, token) => {
                if(err){
                    logToFile('JWT Error: ' + err)
                    res.status(400).send(err);
                    return;
                }else{
                    logToFile('Welcome: ' + req.body.sys_user_id)
                    userToken = token
                    result.recordset[0].jwtToken = token
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                }
            })
        }else{
            res.status(400).send('Error de Inicio de Sesión');
            return;
        }
    })

});
app.get(process.env.iisVirtualPath+'spSysUserMainData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_profile_id', sql.Int, req.query.sys_profile_id )
            .input('sys_user_language', sql.VarChar(25), req.query.sys_user_language )
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .execute('spSysUserMainData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysUserMainData:  " + ((new Date() - start) / 1000) + ' secs')
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spMyUnreadNotifications', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .execute('spMyUnreadNotifications', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMyUnreadNotifications:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spMyNotificationsContacts', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .execute('spMyNotificationsContacts', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMyNotificationsContacts:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spMyNotificationsContactMessages', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('contactUserCode', sql.Int, req.query.contactUserCode )
            .execute('spMyNotificationsContactMessages', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMyNotificationsContactMessages:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'uploadFile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                logToFile('flag00')
                /*if (!req.files){
                    logToFile('Error en uploadFile (no se recibió archivo)')
                    res.status(400).send('Error en uploadFile (no se recibió archivo)');
                    return;
                }*/
                var fileName = Object.keys(req.files)[0]
                logToFile('flag01')
                let sampleFile = req.files[fileName]
                logToFile('flag02')
                logToFile('Upload ' + process.env.filesPath + req.query.upload_file_name)
                sampleFile.mv(process.env.filesPath + req.query.upload_file_name, function(err) {
                    if(err){
                        logToFile('Error escribiendo archivo (uploadFile): ' + JSON.stringify(err))
                        res.status(400).send(err);
                        return;
                    }
                    new sql.Request(connectionPool)
                    .input('attach_id', sql.VarChar(500), req.query.attach_id )
                    .execute('sp_attachs_uploaded', (err, result) => {
                        logToFile("Request:  " + req.originalUrl)
                        logToFile("Perf sp_attachs_uploaded:  " + ((new Date() - start) / 1000) + ' secs' )

                        if(err){
                            logToFile("DB Error:  " + err.procName)
                            logToFile("Error:  " + JSON.stringify(err.originalError.info))
                            res.status(400).send(err.originalError);
                            return;
                        }
                        res.setHeader('content-type', 'application/json');
                        res.status(200).send(result.recordset);
                    })

                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.get(process.env.iisVirtualPath+'downloadFile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            logToFile("Request:  " + req.originalUrl)
            logToFile("Perf downloadFile:  " + ((new Date() - start) / 1000) + ' secs' )
            res.download((process.env.filesPath + "//" + req.query.fileName))
        }
    })
})
app.get(process.env.iisVirtualPath+'downloadTempFile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            logToFile("Request:  " + req.originalUrl)
            logToFile("Perf downloadFile:  " + ((new Date() - start) / 1000) + ' secs' )
            res.download((process.env.tempFilesPath + "//" + req.query.fileName), function (err) {
                if (err) {
                    logToFile("Error downloading File...")
                } else {
                    logToFile("Deleting File: " + process.env.tempFilesPath + req.query.fileName);
                    fs.unlink(process.env.tempFilesPath + req.query.fileName, (err) => {
                        if (err) {
                            logToFile("Deleting File error: " + process.env.tempFilesPath + req.query.fileName);
                        }
                    });
                    logToFile("Temp file deleted")
                }
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spAttachGenerateID', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('original_file_name', sql.VarChar(500), req.body.original_file_name )
                .input('file_type', sql.VarChar(sql.MAX), req.body.file_type )
                .input('file_size', sql.VarChar(sql.Int), req.body.file_size )
                .input('row_id', sql.Int, req.body.row_id )
                .execute('spAttachGenerateID', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAttachGenerateID:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.get(process.env.iisVirtualPath+'spGetMailFormData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            //Generates PDF if exists URL
            if(req.query.moduleReportURL){
                logToFile("Generate PDF:  " + req.originalUrl)
                logToFile("Generate PDF as :  " + req.query.uid)
                
                //Config Request
                const agent = new https.Agent({ rejectUnauthorized: false });
                const options = {
                    url: req.query.moduleReportURL //url: 'https://localhost/ReportServer?/mktPO_1&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=5'
                    ,followRedirect: true
                    ,followAllRedirects: true
                    ,jar: true
                    ,agent: agent
                    ,strictSSL: false
                };
                request(options).on('error', function(err) {
                    logToFile("Error:  " + JSON.stringify(err))
                    res.status(400).send(err);
                    return;
                }).pipe(fs.createWriteStream((process.env.tempFilesPath + req.query.uid + '.pdf')))
            }
            
              
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(25), req.query.userLanguage )
            .input('moduleName', sql.VarChar(500), req.query.moduleName )
            .input('row_id', sql.Int, req.query.row_id )
            .execute('spGetMailFormData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spGetMailFormData:  " + ((new Date() - start) / 1000) + ' secs')
                if(err){
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                //Push Attachment to Result (Using Public Internet Path to Temp Files)
                if(req.query.moduleReportURL){
                    let attachments = [{
                         fileName: req.query.moduleName+'_'+req.query.row_id+'.pdf'
                        ,uploadFilename: req.query.uid + '.pdf'
                    }]
                    result.recordset[0].attachments = attachments
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'sendUserMail', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                let transporter = nodemailer.createTransport({
                    host: process.env.notifyMailHost,
                    port: process.env.notifyMailPort,
                    secure: process.env.notifyMailSecure,
                    auth: {
                      user: process.env.notifyMailUser,
                      pass: process.env.notifyMailPass,
                    },
                    tls: {
                        rejectUnauthorized: false// do not fail on invalid certs
                    },
                });
                //convert Attachments
                let attachments = []
                if(req.body.attachments){
                    JSON.parse(req.body.attachments).map(x=>
                        attachments.push({
                             filename: x.fileName
                            ,path: process.env.tempFilesPath + x.uploadFilename
                        })
                    )
                }
                var mailOptions = {
                    from: '"'+req.body.senderName+'" <'+process.env.notifyMailUser+'>', //from debe contener entre <> la misma cuenta que se usa en el Transporter (podría sacarla de [auth.user] )
                    replyTo: req.body.senderMail,
                    to: req.body.destinations,
                    subject: req.body.subjectText,
                    text: req.body.bodyText,
                    html: req.body.bodyText,
                    attachments: attachments
                };

                logToFile("Sending Mail...")
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        logToFile("Error sending mail")
                        logToFile(error)
                        res.status(400).send(error);
                        return;
                    }
                    //logToFile("Message Message: " + info.messageId)
                    
                    logToFile("Message Sent: " + JSON.stringify(info) )
                    if(req.body.attachments){
                        JSON.parse(req.body.attachments).map(x=>{
                            logToFile("Deleting File: " + process.env.tempFilesPath + x.uploadFilename);
                            fs.unlink(process.env.tempFilesPath + x.uploadFilename, (err) => {
                                if (err) {
                                    logToFile("Deleting File error: " + process.env.tempFilesPath + x.uploadFilename);
                                }
                            });
                        })
                    }
                    logToFile("Perf spGetMailFormData:  " + ((new Date() - start) / 1000) + ' secs')
                    res.status(200).send(info);
                });
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'generateEMLMail', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                let attachments = []
                if(req.body.attachments){
                    JSON.parse(req.body.attachments).map(x=>
                        attachments.push({
                             name: x.fileName
                            ,data: fs.readFileSync(process.env.tempFilesPath + x.uploadFilename),
                            //,path: process.env.tempFilesPath + x.uploadFilename
                        })
                    )
                }
                let destinations = [];
                if(req.body.destinations&&req.body.destinations){
                    req.body.destinations.replace(';',',')
                    req.body.destinations.split(',').map(x=>{
                        destinations.push({
                            //name: '"'+x+'"', 
                            email: x
                        });
                    });
                }
                if(destinations.length<=0){
                    destinations = [{name: req.body.senderMail, email: req.body.senderMail}]
                }
                var data = {
                    from: req.body.senderMail,
                    headers: { "X-Unsent": "1"},
                    to: destinations,
                    subject: req.body.subjectText,
                    html: req.body.bodyText,
                    attachments: attachments
                };
                logToFile("Generating EML: " + process.env.tempFilesPath + req.body.uid + '.eml');
                emlFormat.build(data, function(error, eml) {
                    if(error){
                        logToFile("Generating EML Error")
                        logToFile(error)
                        res.status(400).send(error);
                        return;
                    }
                    fs.writeFileSync(process.env.tempFilesPath + req.body.uid + '.eml', eml);
                    logToFile("EML File created: " + process.env.tempFilesPath + req.body.uid + '.eml')
                    let resultado = {
                        fileName: 'Mail.eml',
                        uploadFilename: req.body.uid + '.eml'
                    }
                    res.status(200).send(resultado);
                });
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion SESSION_OTHERS

//#region DynamicData
app.get(process.env.iisVirtualPath+'spSysModulesSelect', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .input('link_name', sql.VarChar(50), req.query.link_name )
            .execute('spSysModulesSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysModulesSelect:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'getData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Variables
                let selectPart = ''
                //Get SELECT
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('sys_company_id', sql.Int, req.body.sys_company_id )
                .input('gridDataSkip', sql.BigInt, req.body.gridDataSkip )
                .input('gridNumberOfRows', sql.BigInt, req.body.gridNumberOfRows )
                .input('gridColumns', sql.VarChar(sql.MAX), req.body.gridColumns )
                .input('filterBy', sql.VarChar(sql.MAX), req.body.filterBy )
                .input('filterSearch', sql.VarChar(100), req.body.filterSearch )
                .input('sortBy', sql.VarChar(50), req.body.sortBy )
                .input('orderBy', sql.VarChar(50), req.body.orderBy )
                .execute('spGetDataSelect', (err, result) => {
                    if(err){
                        logToFile("DB Error 1:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    try{
                        selectPart = result.recordset[0].selectPart
                        //Run QUERY
                        //logToFile("selectPart: " + selectPart)//deja el query en log.txt
                        new sql.Request(connectionPool)
                        .query(selectPart, (err, result) => {
                            if(err){
                                logToFile("DB Error 2:  " + selectPart)
                                logToFile("Error:  " + JSON.stringify(err.originalError.info))
                                res.status(400).send(err.originalError);
                                return;
                            }
                            res.setHeader('content-type', 'application/json');
                            res.status(200).send(result.recordset);
                        })
                    }catch(execp){
                        logToFile('Service Error: ' + JSON.stringify(execp))
                        res.status(400).send(execp);
                        return;
                    }
                })
            }catch(ex){
                logToFile("Service Error:")
                logToFile(JSON.stringify(ex))
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'getLookupData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            let query = ''
            new sql.Request(connectionPool)
            .input('link_name', sql.VarChar(50), req.body.link_name )
            .input('db_column', sql.VarChar(50), req.body.db_column )
            .input('sys_user_code', sql.Int, req.body.sys_user_code )
            .input('sys_company_id', sql.Int, req.body.sys_company_id )
            .execute('spGetModuleColumnSearchData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spGetModuleColumnSearchData:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                try{
                    logToFile('Query: ' + result.recordset[0].query);
                    query = result.recordset[0].query
                    //Run QUERY
                    new sql.Request(connectionPool)
                    .query(query, (queryError, queryR) => {
                        logToFile("Perf internalQuery:  " + ((new Date() - start) / 1000) + ' secs')
                        if(queryError){
                            logToFile('Database Error inside getLookupData: ' + JSON.stringify(queryError.originalError.info))
                            res.status(400).send(queryError.originalError);
                            return;
                        }
                        res.setHeader('content-type', 'application/json');
                        res.status(200).send(queryR.recordset);
                    })
                }catch(execp){
                    logToFile("Service Error")
                    logToFile(execp)
                    logToFile("Error:  " + JSON.stringify(execp))
                    res.status(400).send(execp);
                    return;
                }
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesColumnsUserUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('columns', sql.VarChar(sql.MAX), req.body.columns )
                .execute('spSysModulesColumnsUserUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysModulesColumnsUserUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesFiltersUserUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('filter_id', sql.Int, req.body.filter_id )
                .input('name', sql.VarChar(250), req.body.name )
                .input('conditions', sql.VarChar(sql.MAX), req.body.conditions )
                .execute('spSysModulesFiltersUserUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysModulesFiltersUserUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesFiltersUserDelete', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('filter_id', sql.Int, req.body.filter_id )
                .execute('spSysModulesFiltersUserDelete', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysModulesFiltersUserDelete:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesFiltersUserDefaultUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('filter_id', sql.Int, req.body.filter_id )
                .execute('spSysModulesFiltersUserDefaultUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysModulesFiltersUserDefaultUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesFiltersUserDefaultUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('link_name', sql.VarChar(50), req.body.link_name )
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('filter_id', sql.Int, req.body.filter_id )
                .execute('spSysModulesFiltersUserDefaultUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysModulesFiltersUserDefaultUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion DynamicData

//#region USERS
app.get(process.env.iisVirtualPath+'spSysUsersSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysUsersSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysUsersSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysUsersUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('sys_user_language', sql.VarChar(25), req.body.sys_user_language )
                .input('currentRow', sql.Int, req.body.currentRow )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysUsersUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysUsersUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysUsersPreferencesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('user_data', sql.VarChar(sql.MAX), req.body.user_data )
                .execute('spSysUsersPreferencesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysUsersPreferencesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'sp_sys_user_picture_upload', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('original_file_name', sql.VarChar(500), req.body.original_file_name )
                .input('file_type', sql.VarChar(sql.MAX), req.body.file_type )
                .input('file_size', sql.VarChar(sql.Int), req.body.file_size )
                .input('editing_sys_user_code', sql.VarChar(sql.Int), req.body.editing_sys_user_code )
                .execute('sp_sys_user_picture_upload', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf sp_sys_user_picture_upload:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion USERS

//#region PROFILES
app.get(process.env.iisVirtualPath+'spSysProfilesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysProfilesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysProfilesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysProfilesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('sys_user_language', sql.VarChar(25), req.body.sys_user_language )
                .input('currentRow', sql.Int, req.body.currentRow )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysProfilesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysProfilesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PROFILES

//#region COMPANIES
app.get(process.env.iisVirtualPath+'spSysCompaniesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysCompaniesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysCompaniesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysCompaniesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('sys_user_language', sql.VarChar(25), req.body.sys_user_language )
                .input('currentRow', sql.Int, req.body.currentRow )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysCompaniesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysCompaniesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion COMPANIES

//#region MODULES
app.get(process.env.iisVirtualPath+'spSysModulesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysModulesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysModulesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysModulesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('sys_user_code', sql.Int, req.body.sys_user_code )
                .input('sys_user_language', sql.VarChar(25), req.body.sys_user_language )
                .input('currentRow', sql.Int, req.body.currentRow )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysModulesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysModulesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion MODULES

//#region NOTIFICATIONS
app.get(process.env.iisVirtualPath+'spNotificationsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spNotificationsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spNotificationsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spNotificationsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spNotificationsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spNotificationsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion NOTIFICATIONS

//#region CHART_ACCOUNTS
app.get(process.env.iisVirtualPath+'spAccAccountsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spAccAccountsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccAccountsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spAccAccountsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spAccAccountsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAccAccountsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion CHART_ACCOUNTS

//#region TAX_MASTER
app.get(process.env.iisVirtualPath+'spSysTaxesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            //.input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysTaxesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysTaxesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysTaxesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                //.input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.currentRow )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysTaxesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysTaxesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion TAX_MASTER

//#region TAXES
app.get(process.env.iisVirtualPath+'spAccTaxesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spAccTaxesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccTaxesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spAccTaxesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spAccTaxesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAccTaxesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion TAXES

//#region PERIODS
app.get(process.env.iisVirtualPath+'spAccPeriodsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spAccPeriodsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccPeriodsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spAccPeriodsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spAccPeriodsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAccPeriodsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PERIODS

//#region PAYTERMS
app.get(process.env.iisVirtualPath+'spAccPaytermsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spAccPaytermsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccPaytermsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spAccPaytermsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spAccPaytermsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAccPaytermsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PERIODS

//#region LOCATIONS
app.get(process.env.iisVirtualPath+'spSysCompLocSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSysCompLocSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysCompLocSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSysCompLocUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysCompLocUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSysCompLocUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion LOCATIONS

//#region PARTNERS
app.get(process.env.iisVirtualPath+'spPartnerMasterSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spPartnerMasterSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spPartnerMasterSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spPartnerMasterUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spPartnerMasterUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spPartnerMasterUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PARTNERS

//#region PARTNERS_GROUPS
app.get(process.env.iisVirtualPath+'spPartnerMasterGroupsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spPartnerMasterGroupsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spPartnerMasterGroupsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spPartnerMasterGroupsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spPartnerMasterGroupsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spPartnerMasterGroupsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PARTNERS_GROUPS

//#region ITEMS
app.get(process.env.iisVirtualPath+'spInvMasterSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvMasterSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvMasterSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvMasterUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spInvMasterUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spInvMasterUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion ITEMS

//#region ITEMS_GROUPS
app.get(process.env.iisVirtualPath+'spInvMasterGroupsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvMasterGroupsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvMasterGroupsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvMasterGroupsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spInvMasterGroupsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spInvMasterGroupsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion ITEMS_GROUPS

//#region WAREHOUSES
app.get(process.env.iisVirtualPath+'spWhMasterSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spWhMasterSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spWhMasterSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spWhMasterUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spWhMasterUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spWhMasterUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion WAREHOUSES

//#region UoM
app.get(process.env.iisVirtualPath+'spInvMasterUoMSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvMasterUoMSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvMasterUoMSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvMasterUoMUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spInvMasterUoMUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spInvMasterUoMUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion UoM

//#region BRANDS
app.get(process.env.iisVirtualPath+'spInvMasterBrandsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvMasterBrandsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvMasterBrandsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvMasterBrandsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spInvMasterBrandsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spInvMasterBrandsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion BRANDS

//#region INVTYPES
app.get(process.env.iisVirtualPath+'spinvMasterTypesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spinvMasterTypesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spinvMasterTypesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spinvMasterTypesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spinvMasterTypesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spinvMasterTypesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion INVTYPES

//#region PURCHASE_REQUESTS
app.get(process.env.iisVirtualPath+'spMktPRSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            logToFile("userCode:  " + req.query.userCode)
            logToFile("userCompany:  " + req.query.userCompany)
            logToFile("userLanguage:  " + req.query.userLanguage)
            logToFile("row_id:  " + req.query.row_id)
            logToFile("editMode:  " + req.query.editMode)
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spMktPRSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPRSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spMktPRUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spMktPRUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spMktPRUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PURCHASE_REQUESTS

//#region PURCHASE_ORDERS
app.get(process.env.iisVirtualPath+'spMktPOSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spMktPOSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPOSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spMktPOSelectmktPR', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            //.input('row_id', sql.Int, req.query.row_id )
            //.input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spMktPOSelectmktPR', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPOSelectmktPR:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spMktPOUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spMktPOUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spMktPOUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PURCHASE_ORDERS

//#region PURCHASE_ORDERS_RETURNS
app.get(process.env.iisVirtualPath+'spMktPORetSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spMktPORetSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPORetSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spMktPORetSelectPending', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('partnerID', sql.Int, req.query.partnerID )
            //.input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spMktPORetSelectPending', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPORetSelectPending:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spMktPORetUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spMktPORetUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spMktPORetUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion PURCHASE_ORDERS_RETURNS

//#region INVENTORY_INCOMING 
app.get(process.env.iisVirtualPath+'spInvKardexIncomingSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvKardexIncomingSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvKardexIncomingSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spInvKardexSelectPending', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('partnerID', sql.Int, req.query.partnerID )
            .input('whID', sql.Int, req.query.whID )
            .input('direction', sql.Int, req.query.direction )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvKardexSelectPending', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvKardexSelectPending:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvKardexIncomingUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spInvKardexIncomingUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spInvKardexIncomingUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion INVENTORY_INCOMING

//#region INVENTORY_OUTGOING
app.get(process.env.iisVirtualPath+'spInvKardexOutgoingSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spInvKardexOutgoingSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvKardexOutgoingSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spInvKardexOutgoingUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spInvKardexOutgoingUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spInvKardexOutgoingUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion INVENTORY_OUTGOING

//#region INVENTORY_QUERY
app.get(process.env.iisVirtualPath+'spInvQueryUserWHSelect', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .execute('spInvQueryUserWHSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvQueryUserWHSelect:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spInvQueryGetData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('whID', sql.Int, req.query.whID )
            .input('gridDataSkip', sql.BigInt, req.query.gridDataSkip )
            .input('gridNumberOfRows', sql.BigInt, req.query.gridNumberOfRows )
            .input('filterSearch', sql.VarChar(100), req.query.filterSearch )
            .input('sortBy', sql.VarChar(50), req.query.sortBy )
            .input('orderBy', sql.VarChar(10), req.query.orderBy )
            .execute('spInvQueryGetData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvQueryGetData:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spInvQueryWhIDInvIDGetData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('whID', sql.Int, req.query.whID )
            .input('invID', sql.Int, req.query.invID )
            .execute('spInvQueryWhIDInvIDGetData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvQueryWhIDInvIDGetData:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spInvQueryWhIDInvIDGetLotData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('whID', sql.Int, req.query.whID )
            .input('invID', sql.Int, req.query.invID )
            .execute('spInvQueryWhIDInvIDGetLotData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spInvQueryWhIDInvIDGetLotData:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
//#endregion INVENTORY_QUERY

//#region ACCMOVES
app.get(process.env.iisVirtualPath+'spAccMovesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spAccMovesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccMovesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spAccMovesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spAccMovesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAccMovesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion ACCMOVES

//#region AP_INVOICES
app.get(process.env.iisVirtualPath+'spAccAPSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spAccAPSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccAPSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.get(process.env.iisVirtualPath+'spAccAPSelectmktPO', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('partnerID', sql.Int, req.query.partnerID)
            .execute('spAccAPSelectmktPO', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccAPSelectmktPO:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spAccAPUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spAccAPUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAccAPUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion AP_INVOICES


//#endregion Version_1_0_0


//#region casLEGAL

//#region casCasesTypes
app.get(process.env.iisVirtualPath+'spCasCasesTypesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spCasCasesTypesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasCasesTypesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spCasCasesTypesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spCasCasesTypesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spCasCasesTypesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion casCasesTypes

//#region casTasksTypes
app.get(process.env.iisVirtualPath+'spCasTasksTypesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spCasTasksTypesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasTasksTypesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spCasTasksTypesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spCasTasksTypesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spCasTasksTypesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion casCasesTypes

//#region casLocations
app.get(process.env.iisVirtualPath+'spCasLocationsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spCasLocationsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasLocationsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spCasLocationsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spCasLocationsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spCasLocationsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion casCasesTypes

//#region casClientes
app.get(process.env.iisVirtualPath+'spCasClientesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spCasClientesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasClientesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spCasClientesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spCasClientesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spCasClientesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion casClientes

//#region casContracts
app.get(process.env.iisVirtualPath+'spCasContractsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spCasContractsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasContractsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spCasContratosUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spCasContratosUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spCasContratosUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion casContratos

//#region CasCases
app.get(process.env.iisVirtualPath+'spCasCasesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spCasCasesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasCasesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spCasCasesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spCasCasesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spCasCasesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion CasCases

//#region casCasesTasks
app.get(process.env.iisVirtualPath+'spCasCasesTasksSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spCasCasesTasksSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasCasesTasksSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spCasCasesTasksUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spCasCasesTasksUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spCasCasesTasksUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion casCasesTasks

//#region casInvoices
app.get(process.env.iisVirtualPath+'spCasInvoicesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spCasInvoicesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasInvoicesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spCasInvoicesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spCasInvoicesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spCasInvoicesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.get(process.env.iisVirtualPath+'spCasInvoicesSelectPending', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('customerID', sql.Int, req.query.customerID )
            .execute('spCasInvoicesSelectPending', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spCasInvoicesSelectPending:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})

//#endregion casInvoices


//#endregion LEGAL


//#region SCHOENSTATT

//#region SCHOENSTATT_PERSONAS
app.get(process.env.iisVirtualPath+'spSchPersonasSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSchPersonasSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSchPersonasSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSchPersonasUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSchPersonasUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSchPersonasUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion SCHOENSTATT_PERSONAS

//#region SCHOENSTATT_GROUPS
app.get(process.env.iisVirtualPath+'spSchGroupsSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSchGroupsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSchGroupsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSchGroupsUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSchGroupsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSchGroupsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion SCHOENSTATT_GROUPS

//#region SCHOENSTATT_SECTORES
app.get(process.env.iisVirtualPath+'spSchSectoresSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSchSectoresSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSchSectoresSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSchSectoresUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSchSectoresUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSchSectoresUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion SCHOENSTATT_SECTORES

//#region SCHOENSTATT_APOSTOLADOS
app.get(process.env.iisVirtualPath+'spSchApostoladosSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSchApostoladosSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSchApostoladosSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSchApostoladosUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSchApostoladosUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSchApostoladosUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion SCHOENSTATT_APOSTOLADOS

//#region SCHOENSTATT_FORMACIONES
app.get(process.env.iisVirtualPath+'spSchFormacionesSelectEdit', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userCompany', sql.Int, req.query.userCompany )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .input('row_id', sql.Int, req.query.row_id )
            .input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spSchFormacionesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSchFormacionesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
                if(err){
                    logToFile("DB Error:  " + err.procName)
                    logToFile("Error:  " + JSON.stringify(err.originalError.info))
                    res.status(400).send(err.originalError);
                    return;
                }
                res.setHeader('content-type', 'application/json');
                res.status(200).send(result.recordset);
            })
        }
    })
})
app.post(process.env.iisVirtualPath+'spSchFormacionesUpdate', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                new sql.Request(connectionPool)
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSchFormacionesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spSchFormacionesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

                    if(err){
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
                })
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion SCHOENSTATT_FORMACIONES

//#endregion SCHOENSTATT


const server = app.listen(process.env.PORT);
logToFile('API started using port ' + process.env.PORT)

//#region WebSocket
function addWebsocketConnection(newConnection){
    try{
        let fileContent = JSON.parse(fs.readFileSync(process.env.websocketsFile));
        fileContent.connections.push(newConnection)
        fs.writeFileSync(process.env.websocketsFile,JSON.stringify(fileContent))
    }catch(ex){
        logToFile('xxx Error en addWebsocketConnection xxx');
        logToFile(JSON.stringify(ex));
    }
}
function removeWebsocketConnection(userID){
    try{
        let fileContent = JSON.parse(fs.readFileSync(process.env.websocketsFile));
        fileContent.connections = fileContent.connections.filter(x => x.userData.userCode != userID)
        fs.writeFileSync(process.env.websocketsFile,JSON.stringify(fileContent))
    }catch(ex){
        logToFile('xxx Error en removeWebsocketConnection xxx');
        logToFile(JSON.stringify(ex));
    }
}


//#region CreateServer
logToFile('Starting Websocket Server...');
const WebSocketServer = new WebSocket.Server({server})//initialize the WebSocket server instance
logToFile('!!!!!!!!!!!!!!!!!!!!Websocket Server created!!');
let startfileContent = {connections:[]};
fs.writeFileSync(process.env.websocketsFile,JSON.stringify(startfileContent))
logToFile('!!!!!!!!!!!!!!!!!!!!Websocket Server file restarted!!');
//#endregion CreateServer

WebSocketServer.on('connection', (ws,request) => {   
    let startIndex = parseInt(request.url.indexOf('userid'));
    startIndex = startIndex + 7;
    let userID = request.url.substring(startIndex,1000)
    let wsID = request.headers['sec-websocket-key']
    let userData = {
         "userCode": userID
        ,"wsID": wsID
    }
    ws['userData'] = userData
    addWebsocketConnection(ws)

    ws.on('message', message => {
        let fileContent = JSON.parse(fs.readFileSync(process.env.websocketsFile));
        //ws.send(message)//send message to All

        WebSocketServer.clients.forEach(function each(client) {
            //valida que exista, y que usuario esté en archivo de conexiones
            if (client.readyState === WebSocket.OPEN && fileContent.connections.some(x=>x.userData.userCode==client.userData.userCode)) {
                logToFile('Enviar mensaje:' + client.userData.userCode);
                client.send(message);
            }
        });
    });

    ws.on('close', (reasonCode,userData) => {
        removeWebsocketConnection(userData)
    })
})
//#endregion WebSocket