//process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';       //allows to get files from https even if certificate invalid
var fileUpload = require('express-fileupload')          //yarn add express-fileupload
var compression = require('compression')                //yarn add compression
var express = require('express');                       //yarn add express -- save
var sql = require('mssql');                             //yarn add mssql -- save
var jwt = require("jsonwebtoken");                      //yarn add jsonwebtoken --save
var request = require('request');                       //yarn add request --save
var httpntlm = require('httpntlm');                 //yarn add httpntlm
var axios = require('axios');                         //yarn add axios --save
var soapRequest = require('easy-soap-request'); //yarn add easy-soap-request
//var curl = require('curl');                           //yarn add curl --save
//var superagent = require('superagent');               //yarn add superagent --save
//var WebSocket  = require("ws");                         //yarn add ws --save
var nodemailer = require("nodemailer");                 //yarn add nodemailer --save
var emlFormat = require("eml-format");                //yarn add eml-format --save
//var socketIO = require("socket.io");                  //yarn add socket.io --save
var ExcelJS = require('exceljs');             //yarn add exceljs --save
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
//#endregion Public_Functions_&_Variables


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
        //NO quiero grabar la clave logToFile("Request:  " + JSON.stringify(req.body))
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
                    new sql.Request(connectionPool)
                    .input('sys_user_code', sql.Int, result.recordset[0].sys_user_code)
                    .input('token', sql.VarChar(sql.MAX), token)
                    .input('device_data', sql.VarChar(sql.MAX), null)//se puede agregar información adicional
                    .execute('spSysLoginLogToken', (errA, resultA) => {
                        if(errA){
                            if(errA&&errA.originalError&&errA.originalError.info){
                                logToFile('DB Error: ' + JSON.stringify(errA.originalError.info))
                            }else{
                                logToFile('DB Error: ' + JSON.stringify(errA.originalError))
                            }
                            res.status(400).send(errA.originalError);
                            return;
                        }
                        
                        logToFile('Welcome: ' + req.body.sys_user_id)
                        userToken = token
                        result.recordset[0].jwtToken = token
                        res.setHeader('content-type', 'application/json');
                        res.status(200).send(result.recordset);
                    })
                }
            })
        }else{
            res.status(400).send('Error de Inicio de Sesión');
            return;
        }
    })

});
app.post(process.env.iisVirtualPath+'sp_sys_users_reset', function (req, res) {
    let start = new Date()
    logToFile('!!! New password Reset attempt for ' + req.body.sys_user_id)
    new sql.Request(connectionPool)
    .input('sys_user_id', sql.VarChar(250), req.body.sys_user_id )
    .input('source_data', sql.VarChar(100), req.ip )
    .input('url_destination', sql.VarChar(250), req.body.url_destination )
    .execute('sp_sys_users_reset', (err, result) => {
        logToFile("Request:  " + req.originalUrl)
        //NO quiero grabar la clave logToFile("Request:  " + JSON.stringify(req.body))
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
            try{
                logToFile("Temp Sent: " + JSON.stringify(result.recordset) )
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

                var mailOptions = {
                    from: '"BITT" <'+process.env.notifyMailUser+'>', //from debe contener entre <> la misma cuenta que se usa en el Transporter (podría sacarla de [auth.user] )
                    //to: req.body.destinations,
                    to: result.recordset[0].destination_address,
                    subject: 'Solicitud de Código Temporal',
                    text: result.recordset[0].destination_message_HTML,
                    html: result.recordset[0].destination_message_HTML
                };

                logToFile("Sending Mail...")
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        logToFile("Error sending mail")
                        logToFile(error)
                        res.status(400).send(error);
                        return;
                    }
                    
                    logToFile("Message Sent: " + JSON.stringify(info) )
                    logToFile("Perf sp_sys_users_reset:  " + ((new Date() - start) / 1000) + ' secs')
                    res.status(200).send(info);
                });
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }else{
            res.status(400).send('Error de Inicio de Sesión');
            return;
        }
    })

});
app.post(process.env.iisVirtualPath+'sp_sys_users_reset_validate', function (req, res) {
    let start = new Date()
    logToFile('!!! New password Reset attempt ' + req.ip )
    new sql.Request(connectionPool)
    .input('sys_user_id', sql.VarChar(250), req.body.sys_user_id )
    .input('sys_user_password', sql.VarChar(100), req.body.sys_user_password )
    .execute('spSysLogin', (err, result) => {
        logToFile("Request:  " + req.originalUrl)
        //NO quiero grabar la clave logToFile("Request:  " + JSON.stringify(req.body))
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
app.get(process.env.iisVirtualPath+'spSysUserMainDataMobile', veryfyToken, function(req, res) {
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
            .execute('spSysUserMainDataMobile', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysUserMainDataMobile:  " + ((new Date() - start) / 1000) + ' secs')
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
                //logToFile('flag00')
                /*if (!req.files){
                    logToFile('Error en uploadFile (no se recibió archivo)')
                    res.status(400).send('Error en uploadFile (no se recibió archivo)');
                    return;
                }*/
                var fileName = Object.keys(req.files)[0]
                //logToFile('flag01')
                let sampleFile = req.files[fileName]
                //logToFile('flag02')
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
                //.input('row_id', sql.Int, req.body.row_id )
                .input('moduleName', sql.VarChar(500), req.body.moduleName )
                .execute('spAttachGenerateID', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
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
app.post(process.env.iisVirtualPath+'saveGridUserState', veryfyToken, function(req, res) {
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
                .input('moduleName', sql.VarChar(500), req.body.moduleName )
                .input('gridName', sql.VarChar(500), req.body.gridName )
                .input('gridState', sql.VarChar(sql.MAX), req.body.gridState )
                .execute('saveGridUserState', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf saveGridUserState:  " + ((new Date() - start) / 1000) + ' secs' )

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
//2021 version 4.6.2
app.post(process.env.iisVirtualPath+'generatePDFandEML', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Create PDF file based on parameters
                const agent = new https.Agent({ rejectUnauthorized: false });
                const options = {
                    url: req.body.mailReportURL //url: 'https://localhost/ReportServer?/mktPO_1&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=5'
                    ,followRedirect: true
                    ,followAllRedirects: true
                    ,jar: true
                    ,agent: agent
                    ,strictSSL: false
                };
                var stream = request(options).on('error', function(err) {
                    logToFile("Error:  " + JSON.stringify(err))
                    res.status(400).send(err);
                    return;
                }).pipe(fs.createWriteStream((process.env.tempFilesPath + req.body.uid + '.pdf')))

                //create attachments variable AFTER file is created (stream finished)
                stream.on('finish', function (){
                    let attachments = []
                    let fileData = null;
                    fileData = fs.readFileSync(process.env.tempFilesPath + req.body.uid + '.pdf');
                    attachments.push({
                        name: req.body.rptName + '.pdf'
                        ,data: fileData,
                        //,path: process.env.tempFilesPath + x.uploadFilename
                    })
                    //fix data for EML generation
                    let destinations = []
                    req.body.destinations.map(x=>{
                        destinations.push({
                            //name: x.contactName,
                            email: x.mail
                        })
                    })
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
                    //Generate EML
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
app.post(process.env.iisVirtualPath+'generatePDFandSEND', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Create PDF file based on parameters
                const agent = new https.Agent({ rejectUnauthorized: false });
                const options = {
                    url: req.body.mailReportURL //url: 'https://localhost/ReportServer?/mktPO_1&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=5'
                    ,followRedirect: true
                    ,followAllRedirects: true
                    ,jar: true
                    ,agent: agent
                    ,strictSSL: false
                };
                var stream = request(options).on('error', function(err) {
                    logToFile("Error:  " + JSON.stringify(err))
                    res.status(400).send(err);
                    return;
                }).pipe(fs.createWriteStream((process.env.tempFilesPath + req.body.uid + '.pdf')))

                //create attachments variable AFTER file is created (stream finished)
                stream.on('finish', function (){
                    let attachments = []
                    attachments.push({
                        filename: req.body.rptName + '.pdf'
                        ,path: process.env.tempFilesPath + req.body.uid + '.pdf'
                    })
                    //fix data for MAIL
                    var mailOptions = {
                        from: '"'+req.body.senderName+'" <'+process.env.notifyMailUser+'>', //from debe contener entre <> la misma cuenta que se usa en el Transporter (podría sacarla de [auth.user] )
                        replyTo: req.body.senderMail,
                        to: req.body.destinations.map(x=>x.mail).join(", "),
                        subject: req.body.subjectText,
                        text: req.body.bodyText,
                        html: req.body.bodyText,
                        attachments: attachments
                    };
                    //create Transporter
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
                    //SendMail
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
                        logToFile("Deleting File: " + process.env.tempFilesPath + req.body.uid + '.pdf');
                        fs.unlink(process.env.tempFilesPath + req.body.uid + '.pdf', (err) => {
                            if (err) {
                                logToFile("Deleting File error: " + process.env.tempFilesPath + req.body.uid + '.pdf');
                            }
                        });
                        logToFile("Perf spGetMailFormData:  " + ((new Date() - start) / 1000) + ' secs')
                        res.status(200).send(info);
                    });
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
//app.post(process.env.iisVirtualPath+'generatePDFandDOWNLOAD', veryfyToken, function(req, res) {
app.get(process.env.iisVirtualPath+'generatePDFandDOWNLOAD', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Create PDF file based on parameters
                logToFile("generatePDFandDOWNLOAD:  " + req.query.reportURL)
                const agent = new https.Agent({ rejectUnauthorized: false });
                const options = {
                    url: req.query.reportURL //url: 'https://localhost/ReportServer?/mktPO_1&rs:format=PDF&sys_user_code=1&sys_user_language=es&sys_user_company=1&row_id=5'
                    ,followRedirect: true
                    ,followAllRedirects: true
                    ,jar: true
                    ,agent: agent
                    ,strictSSL: false
                    ,'cache-control': 'no-cache'
                };
                logToFile("Creando:  " + process.env.tempFilesPath + req.query.fileName )
                var stream = request(options).on('error', function(err) {
                    logToFile("Error:  " + JSON.stringify(err))
                    res.status(400).send(err);
                    return;
                //}).pipe(fs.createWriteStream((process.env.tempFilesPath + req.body.uid + '.pdf')))
                }).pipe(fs.createWriteStream((process.env.tempFilesPath + req.query.fileName )))

                //create attachments variable AFTER file is created (stream finished)
                stream.on('finish', function (){
                    logToFile("Creado finish:  " + process.env.tempFilesPath + req.query.fileName )
                    res.download(process.env.tempFilesPath + req.query.fileName)
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
app.post(process.env.iisVirtualPath+'spSysTokensMobileUpdate', veryfyToken, function(req, res) {
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
                .input('token', sql.VarChar(sql.MAX), req.body.token )
                .input('deviceData', sql.VarChar(sql.MAX), req.body.deviceData )
                .execute('spSysTokensMobileUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysTokensMobileUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
app.get(process.env.iisVirtualPath+'pbirsGetPDF', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Login to PBIRS and Create PDF file based on parameters
                logToFile("pbirsGetPDF: " + req.query.reportURL)
                httpntlm.get(
                    {
                        url: req.query.reportURL,
                        username: process.env.rptUser,
                        password: process.env.rptPwd,
                        workstation: 'localhost',
                        domain: '',
                        binary: true,
                        strictSSL: false,
                        rejectUnauthorized: false
                    }, function (err, response){
                        if(err){
                            logToFile("error getting pbirs file !!!!!!!!!!!!!!!!!");
                            logToFile(err);
                            res.status(400).send(ex);
                            return;
                        }
                        //Creo Archivo
                        fs.writeFile(
                            (process.env.tempFilesPath + req.query.pdfName)
                            ,response.body
                            ,function (error2) {
                                if(error2){
                                    logToFile("Error creating pbirs pdf file:");
                                    res.status(400).send(error2);
                                    return;
                                }
                                res.download(process.env.tempFilesPath + req.query.pdfName)
                            }
                        )
                    }
                )

            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'pbirsGetEML', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Login to PBIRS and Create PDF file based on parameters
                logToFile("pbirsGetEML: " + req.body.mailReportURL)
                httpntlm.get(
                    {
                        url: req.body.mailReportURL,
                        username: process.env.rptUser,
                        password: process.env.rptPwd,
                        workstation: 'localhost',
                        domain: '',
                        binary: true,
                        strictSSL: false,
                        rejectUnauthorized: false
                    }, function (err, response){
                        if(err){
                            logToFile("error getting pbirs_eml file !!!!!!!!!!!!!!!!!");
                            logToFile(err);
                            res.status(400).send(ex);
                            return;
                        }
                        //Creo Archivo PDF
                        fs.writeFile(
                            (process.env.tempFilesPath + req.body.rptName)
                            ,response.body
                            ,function (error2) {
                                if(error2){
                                    logToFile("Error creating pbirs pdf file:");
                                    res.status(400).send(error2);
                                    return;
                                }
                                logToFile("pbirs pdf file created: " + process.env.tempFilesPath + req.body.rptName);
                                
                                //Read attachments
                                let attachments = []
                                let fileData = null;
                                fileData = fs.readFileSync(process.env.tempFilesPath + req.body.rptName);
                                attachments.push({
                                    name: req.body.rptName,
                                    data: fileData,
                                })
                                //fix data for EML generation
                                let destinations = []
                                req.body.destinations.map(x=>{
                                    destinations.push({
                                        //name: x.contactName,
                                        email: x.mail
                                    })
                                })
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
                                //delete PDF
                                fs.unlink(process.env.tempFilesPath + req.body.rptName, (err) => {
                                    if (err) {
                                        logToFile("Deleting File error: " + process.env.tempFilesPath + req.body.rptName);
                                    }
                                    logToFile("File deleted: " + process.env.tempFilesPath + req.body.rptName);
                                });
                                //Generate EML
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

                            }
                        )
                        

                      
                    }
                )

            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
app.post(process.env.iisVirtualPath+'pbirsSendMail', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                //Login to PBIRS and Create PDF file based on parameters
                logToFile("pbirsSendMail: " + req.body.mailReportURL)
                httpntlm.get(
                    {
                        url: req.body.mailReportURL,
                        username: process.env.rptUser,
                        password: process.env.rptPwd,
                        workstation: 'localhost',
                        domain: '',
                        binary: true,
                        strictSSL: false,
                        rejectUnauthorized: false
                    }, function (err, response){
                        if(err){
                            logToFile("error getting pbirs_eml file !!!!!!!!!!!!!!!!!");
                            logToFile(err);
                            res.status(400).send(ex);
                            return;
                        }
                        //Creo Archivo PDF
                        fs.writeFile(
                            (process.env.tempFilesPath + req.body.rptName)
                            ,response.body
                            ,function (error2) {
                                if(error2){
                                    logToFile("Error creating pbirs pdf file:");
                                    res.status(400).send(error2);
                                    return;
                                }
                                logToFile("pbirs pdf file created: " + process.env.tempFilesPath + req.body.rptName);
                                
                                //Read attachments
                                let attachments = []
                                attachments.push({
                                    filename: req.body.rptName
                                    ,path: process.env.tempFilesPath + req.body.rptName
                                })
                                //fix data for MAIL
                                var mailOptions = {
                                    from: '"'+req.body.senderName+'" <'+process.env.notifyMailUser+'>', //from debe contener entre <> la misma cuenta que se usa en el Transporter (podría sacarla de [auth.user] )
                                    replyTo: req.body.senderMail,
                                    to: req.body.destinations.map(x=>x.mail).join(", "),
                                    subject: req.body.subjectText,
                                    text: req.body.bodyText,
                                    html: req.body.bodyText,
                                    attachments: attachments
                                };

                                //create Transporter
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

                                //SendMail
                                logToFile("Sending Mail...")
                                logToFile("mailOptions: " + JSON.stringify(mailOptions));
                                transporter.sendMail(mailOptions, (error, info) => {
                                    if (error) {
                                        logToFile("Error sending mail")
                                        logToFile(error)
                                        logToFile("Deleting Sending Mail File: " + process.env.tempFilesPath + req.body.rptName);
                                        fs.unlink(process.env.tempFilesPath + req.body.rptName, (err) => {
                                            if (err) {
                                                logToFile("Deleting File error: " + process.env.tempFilesPath + req.body.rptName);
                                            }
                                        });
                                        res.status(400).send(error);
                                        return;
                                    }
                                    //logToFile("Message Message: " + info.messageId)
                                    
                                    logToFile("Message Sent: " + JSON.stringify(info) )
                                    logToFile("Deleting Sending Mail File: " + process.env.tempFilesPath + req.body.rptName);
                                    fs.unlink(process.env.tempFilesPath + req.body.rptName, (err) => {
                                        if (err) {
                                            logToFile("Deleting File error: " + process.env.tempFilesPath + req.body.rptName);
                                        }
                                    });
                                    logToFile("Perf spGetMailFormData:  " + ((new Date() - start) / 1000) + ' secs')
                                    res.status(200).send(info);
                                });
                            }
                        )
                    }
                )

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
app.get(process.env.iisVirtualPath+'spSysReportsSelect', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('userCode', sql.Int, req.query.userCode )
            .input('userLanguage', sql.VarChar(25), req.query.userLanguage )
            .input('rootName', sql.VarChar(100), req.query.rootName )
            .execute('spSysReportsSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysReportsSelect:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spSysReportsUpdate', veryfyToken, function(req, res) {
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
                .input('sys_report_id', sql.VarChar(10), req.body.sys_report_id )
                .input('newAutoOpenState', sql.Bit, req.body.newAutoOpenState )
                .execute('spSysReportsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spSysReportsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
app.get(process.env.iisVirtualPath+'spSysModulesSelectLookupData', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .input('sys_company_id', sql.Int, req.query.sys_company_id )
            .input('link_name', sql.VarChar(50), req.query.link_name )
            .execute('spSysModulesSelectLookupData', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysModulesSelectLookupData:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spSysModulesSelectLookupDataMobile', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            new sql.Request(connectionPool)
            .input('sys_user_code', sql.Int, req.query.sys_user_code )
            .input('sys_company_id', sql.Int, req.query.sys_company_id )
            .input('link_name', sql.VarChar(50), req.query.link_name )
            .execute('spSysModulesSelectLookupDataMobile', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spSysModulesSelectLookupDataMobile:  " + ((new Date() - start) / 1000) + ' secs' )
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
                        logToFile("selectPart: " + selectPart)//deja el query en log.txt
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
app.post(process.env.iisVirtualPath+'getDataDX', veryfyToken, function(req, res) {
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
                .input('select', sql.VarChar(sql.MAX), req.body.select )
                .input('take', sql.BigInt, req.body.take )
                .input('skip', sql.BigInt, req.body.skip )
                .input('searchValue', sql.VarChar(sql.MAX), req.body.searchValue )
                .input('filter', sql.VarChar(sql.MAX), req.body.filter )
                .input('sortBy', sql.VarChar(sql.MAX), req.body.sortBy )
                .execute('spGetDataSelectDX', (err, result) => {
                    if(err){
                        logToFile("DB Error 1:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    res.setHeader('content-type', 'application/json');
                    res.status(200).send(result.recordset);
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
app.post(process.env.iisVirtualPath+'getLookupDataDX', veryfyToken, function(req, res) {
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
            .input('searchValue', sql.VarChar(50), req.body.searchValue )
            .execute('spGetModuleColumnSearchDataDX', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spGetModuleColumnSearchDataDX:  " + ((new Date() - start) / 1000) + ' secs' )
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
                            logToFile('Database Error inside getLookupDataDX: ' + JSON.stringify(queryError.originalError.info))
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
                .input('shouldWrapCellText', sql.Bit, req.body.shouldWrapCellText )
                .input('tableLines', sql.VarChar(50), req.body.tableLines )
                .execute('spSysModulesColumnsUserUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                .input('is_system', sql.Bit, req.body.is_system )
                .execute('spSysModulesFiltersUserDefaultUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysUsersUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    //NO quiero registrar la imagen logToFile("Request:  " + JSON.stringify(req.body))
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
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('userLanguage', sql.VarChar(50), req.body.userLanguage )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysProfilesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysCompaniesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                .input('userCode', sql.Int, req.body.userCode )
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysModulesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                .input('userCompany', sql.Int, req.body.userCompany )
                .input('row_id', sql.Int, req.body.row_id )
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spSysTaxesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
            /*
            .input('gridDataSkip', sql.BigInt, req.query.gridDataSkip )
            .input('gridNumberOfRows', sql.BigInt, req.query.gridNumberOfRows )
            .input('filterSearch', sql.VarChar(100), req.query.filterSearch )
            .input('sortBy', sql.VarChar(50), req.query.sortBy )
            .input('orderBy', sql.VarChar(10), req.query.orderBy )
            */
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
app.get(process.env.iisVirtualPath+'spAccBalanceChart', veryfyToken, function(req, res) {
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
            .input('startDate', sql.VarChar(50), req.query.startDate )
            .input('stopDate', sql.VarChar(50), req.query.stopDate )
            .execute('spAccBalanceChart', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccBalanceChart:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spAccBalanceChartDetails', veryfyToken, function(req, res) {
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
            .input('startDate', sql.VarChar(50), req.query.startDate )
            .input('stopDate', sql.VarChar(50), req.query.stopDate )
            .input('account_id', sql.Int, req.query.account_id )
            .execute('spAccBalanceChartDetails', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccBalanceChartDetails:  " + ((new Date() - start) / 1000) + ' secs' )
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
//#endregion ACCMOVES

//#region spAccPaymentsRelSelect
app.get(process.env.iisVirtualPath+'spAccPaymentsRelSelect', veryfyToken, function(req, res) {
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
            .input('accTypeID', sql.Int, req.query.accTypeID )
            .input('row_id', sql.Int, req.query.row_id )
            .execute('spAccPaymentsRelSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccPaymentsRelSelect:  " + ((new Date() - start) / 1000) + ' secs' )
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
//#endregion spAccPaymentsRelSelect

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
                    logToFile("Request:  " + JSON.stringify(req.body))
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

//#region ACCRET_Retenciones
app.get(process.env.iisVirtualPath+'spAccRETSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spAccRETSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccRETSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spAccRETSelectPendingInvoices', veryfyToken, function(req, res) {
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
            .execute('spAccRETSelectPendingInvoices', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccRETSelectPendingInvoices:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spAccRETUpdate', veryfyToken, function(req, res) {
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
                .execute('spAccRETUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAccRETUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
app.post(process.env.iisVirtualPath+'spAccRETAsistantUpdate', veryfyToken, function(req, res) {
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
                .execute('spAccRETAsistantUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Perf spAccRETAsistantUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion ACCRET_Retenciones

//#region accPaymentMethods
app.get(process.env.iisVirtualPath+'spAccPaymentMethodsSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spAccPaymentMethodsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccPaymentMethodsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spAccPaymentMethodsUpdate', veryfyToken, function(req, res) {
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
                .execute('spAccPaymentMethodsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spAccPaymentMethodsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion accPaymentMethods

//#region AccvoucherOut
app.get(process.env.iisVirtualPath+'spAccvoucherOutSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spAccvoucherOutSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccvoucherOutSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spAccvoucherOutUpdate', veryfyToken, function(req, res) {
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
                .execute('spAccvoucherOutUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spAccvoucherOutUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
app.get(process.env.iisVirtualPath+'spAccvoucherOutSelectaccAP', veryfyToken, function(req, res) {
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
            .execute('spAccvoucherOutSelectaccAP', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccvoucherOutSelectaccAP:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spAccVoucherOutAssistant', veryfyToken, function(req, res) {
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
            .execute('spAccVoucherOutAssistant', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccVoucherOutAssistant:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spAccVoucherOutAssistantUpdate', veryfyToken, function(req, res) {
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
                .input('editRecord', sql.VarChar(sql.MAX), req.body.editRecord )
                .execute('spAccVoucherOutAssistantUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spAccVoucherOutAssistantUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion AccvoucherOut

//#region AccConciliations
app.get(process.env.iisVirtualPath+'spAccConciliationSelectEdit', veryfyToken, function(req, res) {
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
            .input('accTypeID', sql.Int, req.query.accTypeID )
            .input('headerID', sql.Int, req.query.headerID )
            .execute('spAccConciliationSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccConciliationSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spAccConciliationVoid', veryfyToken, function(req, res) {
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
                .input('userLanguage', sql.VarChar(50), req.body.userLanguage )
                .input('headerID', sql.Int, req.body.headerID )
                .execute('spAccConciliationVoid', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spAccConciliationVoid:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion AccConciliations

//#region RETENCIONES
app.get(process.env.iisVirtualPath+'spAccRetOutAssistant', veryfyToken, function(req, res) {
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
            .execute('spAccRetOutAssistant', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccRetOutAssistant:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spAccRetOutAssistantDocsByPartner', veryfyToken, function(req, res) {
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
            .execute('spAccRetOutAssistantDocsByPartner', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spAccRetOutAssistantDocsByPartner:  " + ((new Date() - start) / 1000) + ' secs' )
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
//#endregion spAccRetOutAssistant

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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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

//#region MFG

//#region mfgLocations
app.get(process.env.iisVirtualPath+'spMfgLocationsSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spMfgLocationsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMfgLocationsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spMfgLocationsUpdate', veryfyToken, function(req, res) {
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
                .execute('spMfgLocationsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spMfgLocationsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion mfgLocations

//#region mfgTypes
app.get(process.env.iisVirtualPath+'spMfgTypesSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spMfgTypesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMfgTypesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spMfgTypesUpdate', veryfyToken, function(req, res) {
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
                .execute('spMfgTypesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spMfgTypesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion mfgLocations

//#region mfgBudget
app.get(process.env.iisVirtualPath+'spMfgBudgetSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spMfgBudgetSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMfgBudgetSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spMfgBudgetUpdate', veryfyToken, function(req, res) {
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
                .execute('spMfgBudgetUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spMfgBudgetUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion mfgBudget

//#region mfgOrders
app.get(process.env.iisVirtualPath+'spMfgOrdersSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spMfgOrdersSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMfgOrdersSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spMfgOrdersUpdate', veryfyToken, function(req, res) {
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
                .execute('spMfgOrdersUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spMfgOrdersUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion mfgOrders

//#region mktMFG
app.get(process.env.iisVirtualPath+'spmktMFGSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spmktMFGSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spmktMFGSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spmktMFGUpdate', veryfyToken, function(req, res) {
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
                .execute('spmktMFGUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spmktMFGUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
app.get(process.env.iisVirtualPath+'spmktMFGSelectBudget', veryfyToken, function(req, res) {
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
            //.input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spmktMFGSelectBudget', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spmktMFGSelectBudget:  " + ((new Date() - start) / 1000) + ' secs' )
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
//#endregion mktMFG

//#region mktMFGret
app.get(process.env.iisVirtualPath+'spmktMFGRetSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spmktMFGRetSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spmktMFGRetSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spmktMFGRetSelectPending', veryfyToken, function(req, res) {
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
            //.input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spmktMFGRetSelectPending', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spmktMFGRetSelectPending:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spmktMFGRetUpdate', veryfyToken, function(req, res) {
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
                .execute('spmktMFGRetUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spmktMFGRetUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion mktMFGret

//#region mktPRD
app.get(process.env.iisVirtualPath+'spMktPRDSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spMktPRDSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPRDSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spMktPRDSelectPending', veryfyToken, function(req, res) {
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
            .execute('spMktPRDSelectPending', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPRDSelectPending:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spMktPRDUpdate', veryfyToken, function(req, res) {
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
                .execute('spMktPRDUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spMktPRDUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion mktPRD

//#region mktPRDRet
app.get(process.env.iisVirtualPath+'spMktPRDRetSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spMktPRDRetSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPRDRetSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spMktPRDRetSelectPending', veryfyToken, function(req, res) {
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
            //.input('editMode', req.query.editMode )//.input('editMode', sql.Bit, req.query.editMode )
            .execute('spMktPRDRetSelectPending', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spMktPRDRetSelectPending:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spMktPRDRetUpdate', veryfyToken, function(req, res) {
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
                .execute('spMktPRDRetUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spMktPRDRetUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion mktPRDRet




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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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
                    logToFile("Request:  " + JSON.stringify(req.body))
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

//#region BITACORA_Places
app.get(process.env.iisVirtualPath+'spBitaplacesSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spBitaplacesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitaplacesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spBitaplacesUpdate', veryfyToken, function(req, res) {
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
                .execute('spBitaplacesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spBitaplacesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion BITACORA_Places

//#region BITACORA_Cars
app.get(process.env.iisVirtualPath+'spBitacarsSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spBitacarsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitacarsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spBitaCarsUpdate', veryfyToken, function(req, res) {
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
                .execute('spBitaCarsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spBitaCarsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion BITACORA_Cars

//#region BITACORA_Events
app.get(process.env.iisVirtualPath+'spBitaPlacesByUser', veryfyToken, function(req, res) {
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
            .execute('spBitaPlacesByUser', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitaPlacesByUser:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spBitaEventsByUserByPLace', veryfyToken, function(req, res) {
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
            .input('placeID', sql.Int, req.query.placeID )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .execute('spBitaEventsByUserByPLace', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitaEventsByUserByPLace:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spBitaeventsSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spBitaeventsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitaeventsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spBitaeventsUpdate', veryfyToken, function(req, res) {
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
                .execute('spBitaeventsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spBitaeventsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion BITACORA_Events

//#region BITACORA_People
app.get(process.env.iisVirtualPath+'spBitaPeopleByUserByPLace', veryfyToken, function(req, res) {
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
            .input('placeID', sql.Int, req.query.placeID )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .execute('spBitaPeopleByUserByPLace', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitaPeopleByUserByPLace:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spBitapeopleSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spBitapeopleSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitapeopleSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spBitapeopleUpdate', veryfyToken, function(req, res) {
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
                .execute('spBitapeopleUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spBitapeopleUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion

//#region BITACORA_Rides
app.get(process.env.iisVirtualPath+'spBitaRidesByUserByPlace', veryfyToken, function(req, res) {
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
            .input('placeID', sql.Int, req.query.placeID )
            .input('userLanguage', sql.VarChar(50), req.query.userLanguage )
            .execute('spBitaRidesByUserByPlace', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitaRidesByUserByPlace:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spBitaridesSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spBitaridesSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spBitaridesSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spBitaridesUpdate', veryfyToken, function(req, res) {
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
                .execute('spBitaridesUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spBitaridesUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion

//#region ENS

//#region ENS_PERSONAS
app.get(process.env.iisVirtualPath+'spEnsPersonasSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spEnsPersonasSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsPersonasSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spEnsPersonasUpdate', veryfyToken, function(req, res) {
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
                .execute('spEnsPersonasUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spEnsPersonasUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
app.get(process.env.iisVirtualPath+'spEnsPersonaSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spEnsPersonaSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsPersonaSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
//#endregion ENS_PERSONAS

//#region ENS_TEAMS
app.get(process.env.iisVirtualPath+'spEnsTeamsSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spEnsTeamsSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsTeamsSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spEnsTeamsUpdate', veryfyToken, function(req, res) {
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
                .execute('spEnsTeamsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spEnsTeamsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion ENS_TEAMS

//#region ENS_SERVICIOS
app.get(process.env.iisVirtualPath+'spEnsServiciosSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spEnsServiciosSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsServiciosSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spEnsServiciosUpdate', veryfyToken, function(req, res) {
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
                .execute('spEnsServiciosUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spEnsServiciosUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion ENS_SERVICIOS

//#region ENS_LIBROS
app.get(process.env.iisVirtualPath+'spEnsLibrosSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spEnsLibrosSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsLibrosSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spEnsLibrosUpdate', veryfyToken, function(req, res) {
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
                .execute('spEnsLibrosUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spEnsLibrosUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion ENS_LIBROS

//#region ENS_JOBSEARCH
app.get(process.env.iisVirtualPath+'spEnsJobSearch', veryfyToken, function(req, res) {
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
            .input('searchString', sql.VarChar(sql.MAX), req.query.searchString )
            .execute('spEnsJobSearch', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsJobSearch:  " + ((new Date() - start) / 1000) + ' secs' )
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
//#endregion ENS_JOBSEARCH

//#region ENS_MEET
app.get(process.env.iisVirtualPath+'spEnsMeetTeamSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spEnsMeetTeamSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsMeetTeamSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spEnsMeetTeamUpdate', veryfyToken, function(req, res) {
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
                .execute('spEnsMeetTeamUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spEnsMeetTeamUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion ENS_MEET

//#region ENS_PILOTAJE
app.get(process.env.iisVirtualPath+'spEnsPilotMeetSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spEnsPilotMeetSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsPilotMeetSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spEnsPilotMeetUpdate', veryfyToken, function(req, res) {
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
                .execute('spEnsPilotMeetUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spEnsPilotMeetUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion ENS_PILOTAJE

//#region ENS_MEET_WORK
app.get(process.env.iisVirtualPath+'spEnsWorkMeetSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spEnsWorkMeetSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsWorkMeetSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spEnsWorkMeetUpdate', veryfyToken, function(req, res) {
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
                .execute('spEnsWorkMeetUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spEnsWorkMeetUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion ENS_MEET_WORK

//#region REWARDS(Comisiones)
app.get(process.env.iisVirtualPath+'spRewMasterSelectEdit', veryfyToken, function(req, res) {
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
            .execute('spRewMasterSelectEdit', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spRewMasterSelectEdit:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.get(process.env.iisVirtualPath+'spRewMasterTableDataSelect', veryfyToken, function(req, res) {
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
            .input('rewTableID', sql.Int, req.query.rewTableID )
            .execute('spRewMasterTableDataSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spRewMasterTableDataSelect:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spRewMasterUpdate', veryfyToken, function(req, res) {
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
                .execute('spRewMasterUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spRewMasterUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
app.get(process.env.iisVirtualPath+'spRewMasterTableDataLookupDataSelect', veryfyToken, function(req, res) {
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
            .input('rewTableID', sql.Int, req.query.rewTableID )
            .input('fieldName', sql.VarChar(250), req.query.fieldName )
            .execute('spRewMasterTableDataLookupDataSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spRewMasterTableDataLookupDataSelect:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spRewMasterGetResults', veryfyToken, function(req, res) {
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
                .input('rewTableID', sql.Int, req.body.rewTableID )
                .input('rewMasterResults', sql.VarChar(sql.MAX), req.body.rewMasterResults )
                .input('rewMasterResultsLines', sql.VarChar(sql.MAX), req.body.rewMasterResultsLines )
                .input('selected', sql.VarChar(sql.MAX), req.body.selected )
                .execute('spRewMasterGetResults', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spRewMasterGetResults:  " + ((new Date() - start) / 1000) + ' secs' )

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
app.post(process.env.iisVirtualPath+'spRewMasterGetResultsDetails', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                const workbook = new ExcelJS.Workbook();
                //1.- Primero ejecuta stored_procedure [spRewMasterGetResults] y el resultado lo inserta en primera hoja
                try{
                    new sql.Request(connectionPool)
                    .input('userCode', sql.Int, req.body.userCode )
                    .input('userCompany', sql.Int, req.body.userCompany )
                    .input('rewTableID', sql.Int, req.body.rewTableID )
                    .input('rewMasterResults', sql.VarChar(sql.MAX), req.body.rewMasterResults )
                    .input('rewMasterResultsLines', sql.VarChar(sql.MAX), req.body.rewMasterResultsLines )
                    .input('selected', sql.VarChar(sql.MAX), req.body.selected )
                    .execute('spRewMasterGetResults', (err, result) => {
                        logToFile("Request:  " + req.originalUrl)
                        logToFile("Request:  " + JSON.stringify(req.body))
                        logToFile("Perf spRewMasterGetResults:  " + ((new Date() - start) / 1000) + ' secs' )
                        start = new Date() //para calcular creación de página
                        if(err){
                            logToFile("DB Error:  " + err.procName)
                            logToFile("Error:  " + JSON.stringify(err.originalError.info))
                            res.status(400).send(err.originalError);
                            return;
                        }
                        logToFile("spRewMasterGetResults creando workSheetResumen")
                        //Crear worksheet Resumen
                        const workSheetResumen = workbook.addWorksheet('Resumen');
                        //Freeze 1a fila
                        workSheetResumen.views = [
                            {state: 'frozen', xSplit: 0, ySplit: 1, activeCell: 'A2'}
                        ];
                        //Agrega Columnas
                        if(result&&result.recordset&&result.recordset[0]){
                            try{
                                let columnas = [];
                                Object.keys(result.recordset[0]).forEach(keyName => { columnas.push({header: keyName, key: keyName, width: 30}) });
                                //logToFile(JSON.stringify(columnas))
                                workSheetResumen.columns = columnas
                            }catch(ex){
                                logToFile('se produjo un error:')
                                logToFile(ex)
                                logToFile(ex.message)
                                res.status(400).send(ex);
                                return
                            }
                        }
                        //Pone en negritas las celdas de la fila 1
                        workSheetResumen.getRow(1).font = { bold: true };
                        //Barre el contenido y lo agrega a la hoja de Resultados
                        workSheetResumen.addRows(result.recordset);
                        logToFile("spRewMasterGetResults workSheetResumen creado")
                        logToFile("Perf workSheetResumen creado:  " + ((new Date() - start) / 1000) + ' secs' )

                      

                        //2.- Ahora, Agrega la hoja de Datos
                        logToFile("spRewMasterGetResults obteniendo detalles...")
                        start = new Date() //para calcular creación de página
                        try{
                            new sql.Request(connectionPool)
                            .input('userCode', sql.Int, req.body.userCode )
                            .input('userCompany', sql.Int, req.body.userCompany )
                            .input('rewTableID', sql.Int, req.body.rewTableID )
                            .input('rewMasterResults', sql.VarChar(sql.MAX), req.body.rewMasterResults )
                            .input('rewMasterResultsLines', sql.VarChar(sql.MAX), req.body.rewMasterResultsLines )
                            .input('selected', sql.VarChar(sql.MAX), req.body.selected )
                            .execute('spRewMasterGetResultsDetails', (errDetails, resultDetails) => {
                                logToFile("Perf spRewMasterGetResultsDetails :  " + ((new Date() - start) / 1000) + ' secs' )
                                if(errDetails){
                                    if(errDetails&&errDetails.originalError&&errDetails.originalError.info){
                                        logToFile('DB Error: ' + JSON.stringify(errDetails.originalError.info))
                                    }else{
                                        logToFile('DB Error: ' + JSON.stringify(errDetails.originalError))
                                    }
                                    res.status(400).send(errDetails.originalError);
                                    return;
                                }
                                start = new Date() //para calcular creación de página
                                logToFile("spRewMasterGetResults creando workSheetDetalles")
                                //Crear worksheet Detalles
                                const workSheetDetalles = workbook.addWorksheet('Detalles');
                                //Freeze 1a fila
                                workSheetDetalles.views = [
                                    {state: 'frozen', xSplit: 0, ySplit: 1, activeCell: 'A2'}
                                ];
                                //Pone 1a Fila en Negritas
                                workSheetDetalles.getRow(1).font = { bold: true };
                                //Agrega Columnas
                                if(resultDetails&&resultDetails.recordset&&resultDetails.recordset[0]){
                                    try{
                                        let columnas = [];
                                        Object.keys(resultDetails.recordset[0]).forEach(keyName => { columnas.push({header: keyName, key: keyName, width: 30}) });
                                        //logToFile(JSON.stringify(columnas))
                                        workSheetDetalles.columns = columnas
                                    }catch(ex){
                                        logToFile('se produjo un error:')
                                        logToFile(ex)
                                        logToFile(ex.message)
                                        res.status(400).send(ex);
                                        return
                                    }
                                }
                                //Barre el contenido y lo agrega a la hoja de Resultados
                                workSheetDetalles.addRows(resultDetails.recordset);
                                logToFile("spRewMasterGetResults workSheetDetalles creado")
                                logToFile("Perf workSheetDetalles creado :  " + ((new Date() - start) / 1000) + ' secs' )

                                //Finaliza Archivo, guardándolo en servidor y lo envía a descargar
                                logToFile("Creando archivo temporal:  " + process.env.tempFilesPath + 'Resultados.xlsx' )
                                workbook.xlsx.writeFile(process.env.tempFilesPath + 'Resultados.xlsx').then(function() {
                                    logToFile("Creado:  " + process.env.tempFilesPath + 'Resultados.xlsx' )
                                    res.download((process.env.tempFilesPath + "//Resultados.xlsx"), function (err) {
                                        logToFile("Downloading File...")
                                        if (err) {
                                            logToFile("Error downloading File...")
                                        } else {
                                            logToFile("Deleting File: " + process.env.tempFilesPath + "//Resultados.xlsx");
                                            fs.unlink(process.env.tempFilesPath + "//Resultados.xlsx", (err) => {
                                                if (err) {
                                                    logToFile("Deleting File error: " + process.env.tempFilesPath + "//Resultados.xlsx");
                                                }
                                                logToFile("File " + process.env.tempFilesPath + "//Resultados.xlsx"  + " deleted")
                                            });
                                        }
                                    })
                                });
                            })
                        }catch(exDetails){
                            logToFile("Service Error (Details")
                            logToFile(exDetails)
                            res.status(400).send(exDetails);
                            return;
                        }
                    })
                }catch(ex){
                    logToFile("Service Error")
                    logToFile(ex)
                    res.status(400).send(ex);
                    return;
                }
            }catch(ex){
                logToFile("Service Error")
                logToFile(ex)
                res.status(400).send(ex);
                return;
            }
        }
    })
})
//#endregion REWARDS(Comisiones)



//#region ENS_Calendar
app.get(process.env.iisVirtualPath+'spEnsEventsSelect', veryfyToken, function(req, res) {
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
            .execute('spEnsEventsSelect', (err, result) => {
                logToFile("Request:  " + req.originalUrl)
                logToFile("Perf spEnsEventsSelect:  " + ((new Date() - start) / 1000) + ' secs' )
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
app.post(process.env.iisVirtualPath+'spEnsEventsUpdate', veryfyToken, function(req, res) {
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
                .execute('spEnsEventsUpdate', (err, result) => {
                    logToFile("Request:  " + req.originalUrl)
                    logToFile("Request:  " + JSON.stringify(req.body))
                    logToFile("Perf spEnsEventsUpdate:  " + ((new Date() - start) / 1000) + ' secs' )

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
//#endregion ENS_Calendar

//#region SDE(Holcim)
app.post(process.env.iisVirtualPath+'sde_GetTag_Out_Sync', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                logToFile('running sde_GetTag_Out_Sync')
                const url = 'https://dev.laseritsconline.com:47489/XISOAPAdapter/MessageServlet?senderParty=PEGASUS_GUARDIA&senderService=EC_PEGASUS&receiverParty=&receiverService=CSQCLNT400&interface=GetTag_Out_Sync&interfaceNamespace=urn:com:lh:logistics:la:pegasus:guardia';
                const sampleHeaders = {
                    'user-agent': 'pegasus',
                    'Content-Type': 'text/xml;charset=UTF-8',
                    'soapAction': 'http://sap.com/xi/WebService/soap1.1',
                    'Authorization': 'Basic cGVnYXN1czpMc3JAMjAxMw=='
                };
                const xmlRequest = req.body.xmlRequest
                logToFile(req.body.xmlRequest)
                soapRequest(
                    { url: url, headers: sampleHeaders, xml: xmlRequest, timeout: 2000 }
                ).then((respuesta)=>{
                    const { response } = respuesta;
                    const { headers, body, statusCode } = response;
                    logToFile(JSON.stringify(headers))
                    logToFile(body)
                    logToFile(statusCode)
                    res.status(statusCode).send(body);
                }).catch((errorWS)=>{
                    logToFile("errorWS")
                    logToFile(errorWS)
                    res.status(400).send(errorWS);
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
app.post(process.env.iisVirtualPath+'sde_PlantTimesV03_Out_Sync', veryfyToken, function(req, res) {
    let start = new Date()
    jwt.verify(req.token, process.env.secretEncryptionJWT, (jwtError, authData) => {
        if(jwtError){
            logToFile("JWT Error:")
            logToFile(jwtError)
            res.status(403).send(jwtError);
        }else{
            try{
                const url = 'https://dev.laseritsconline.com:47489/XISOAPAdapter/MessageServlet?senderParty=PEGASUS_PLANTA&senderService=EC_PEGASUS&receiverParty=&receiverService=&interface=PlantTimesV03_Out_Sync&interfaceNamespace=urn:com:lh:logistics:la:pegasus:planta';
                const sampleHeaders = {
                    'user-agent': 'pegasus',
                    'Content-Type': 'text/xml;charset=UTF-8',
                    'soapAction': 'http://sap.com/xi/WebService/soap1.1',
                    'Authorization': 'Basic cGVnYXN1czpMc3JAMjAxMw=='
                };
                const xmlRequest = req.body.xmlRequest
                //<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:lh:logistics:la:pegasus:planta"> <soapenv:Header/> <soapenv:Body> <urn:PlantTimesV03Request> <PAIS>EC</PAIS> <CENTRO>ACB0</CENTRO> <FECHA>2021-06-18</FECHA> <HORA>09:35:12</HORA> <IDANTENA>ACVIGIN</IDANTENA> <IDTAG>EGSI2736</IDTAG> <PESO></PESO> <PRECINTOS></PRECINTOS> <PESO_MANUAL></PESO_MANUAL> <PESO_TANDEM> <CAPAC></CAPAC> </PESO_TANDEM> <TKNUM>63401533</TKNUM> <PESO_TARA_1_PARC></PESO_TARA_1_PARC> <PESO_BRUTO_1_PARC></PESO_BRUTO_1_PARC> <PESO_TARA_2_PARC></PESO_TARA_2_PARC> <PESO_BRUTO_2_PARC></PESO_BRUTO_2_PARC> <VBELN>330101406</VBELN> <PRECINTOS_2></PRECINTOS_2> <PONTO_CARGA></PONTO_CARGA> <CONTINGENCIA></CONTINGENCIA> <T_DADOS_ENTREGA> <VBELN>330102016</VBELN> <REF_EXT>X1234</REF_EXT> </T_DADOS_ENTREGA> </urn:PlantTimesV03Request> </soapenv:Body> </soapenv:Envelope>
                //const xmlRequest = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:com:lh:logistics:la:pegasus:planta"> <soapenv:Header/> <soapenv:Body> <urn:PlantTimesV03Request> <PAIS>EC</PAIS> <CENTRO>ACB0</CENTRO> <FECHA>2021-06-18</FECHA> <HORA>09:35:12</HORA> <IDANTENA>ACVIGIN</IDANTENA> <IDTAG>EGSI2736</IDTAG> <PESO></PESO> <PRECINTOS></PRECINTOS> <PESO_MANUAL></PESO_MANUAL> <PESO_TANDEM> <CAPAC></CAPAC> </PESO_TANDEM> <TKNUM>63401533</TKNUM> <PESO_TARA_1_PARC></PESO_TARA_1_PARC> <PESO_BRUTO_1_PARC></PESO_BRUTO_1_PARC> <PESO_TARA_2_PARC></PESO_TARA_2_PARC> <PESO_BRUTO_2_PARC></PESO_BRUTO_2_PARC> <VBELN>330101406</VBELN> <PRECINTOS_2></PRECINTOS_2> <PONTO_CARGA></PONTO_CARGA> <CONTINGENCIA></CONTINGENCIA> <T_DADOS_ENTREGA> <VBELN>330102016</VBELN> <REF_EXT>X1234</REF_EXT> </T_DADOS_ENTREGA> </urn:PlantTimesV03Request> </soapenv:Body> </soapenv:Envelope>'
                logToFile('running sde_PlantTimesV03_Out_Sync')
                logToFile(req.body.xmlRequest)
                soapRequest(
                    { url: url, headers: sampleHeaders, xml: xmlRequest, timeout: 2000 }
                ).then((respuesta)=>{
                    const { response } = respuesta;
                    const { headers, body, statusCode } = response;
                    logToFile(JSON.stringify(headers))
                    logToFile(body)
                    logToFile(statusCode)
                    res.status(statusCode).send(body);
                }).catch((errorWS)=>{
                    logToFile("errorWS")
                    logToFile(errorWS)
                    res.status(400).send(errorWS);
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
//#endregion SDE(Holcim)



const server = app.listen(process.env.PORT);
logToFile('API started using port ' + process.env.PORT)

/*
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
*/