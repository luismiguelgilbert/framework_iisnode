var express = require('express');           //yarn add express -- save
var sql = require('mssql');                 //yarn add mssql -- save
var jwt = require("jsonwebtoken");          //yarn add jsonwebtoken --save
var app = express();
var fs = require('fs');
var bodyParser = require('body-parser');

var logToFile = function(message){ fs.appendFile(process.env.logPathFile, new Date().toISOString() + '\t' + message + '\r\n', (err) => { if (err) throw err; } ); }

logToFile('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
logToFile('API starting...')

//#region Public_Functions_&_Variables
app.use(bodyParser.json({limit: '50mb'}));  //Use bodyParser, and set file size
app.use(bodyParser.urlencoded({limit: '50mb', extended: true})); //Use bodyParser, and set file size
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");//Enabling CORS 
    res.header("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, contentType, Content-Type, Accept, Authorization");
    next();
});

var connectionPool = new sql.ConnectionPool(process.env.dbConfig, (err, pool) => {
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

//#endregion


//#region Version_1

//#region SESSION
app.post(process.env.iisVirtualPath+'spSysLogin', function (req, res) {
    let start = new Date()
    logToFile('New Login attempt')
    logToFile('Usuario: ' + req.body.sys_user_id + ' (' + req.ip + ')')
    new sql.Request(connectionPool)
    .input('sys_user_id', sql.VarChar(250), req.body.sys_user_id )
    .input('sys_user_password', sql.VarChar(100), req.body.sys_user_password )
    .execute('spSysLogin', (err, result) => {
        logToFile("Request:  " + req.originalUrl)
        logToFile("Perf spSysLogin:  " + ((new Date() - start) / 1000) + ' secs' )
        if(err){
            logToFile('DB Error: ' + JSON.stringify(err.originalError.info))
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
//#endregion Login

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
                        logToFile("DB Error:  " + err.procName)
                        logToFile("Error:  " + JSON.stringify(err.originalError.info))
                        res.status(400).send(err.originalError);
                        return;
                    }
                    try{
                        selectPart = result.recordset[0].selectPart
                        //Run QUERY
                        new sql.Request(connectionPool)
                        .query(selectPart, (err, result) => {
                            if(err){
                                logToFile("DB Error:  " + err.procName)
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

//#endregion Version_1

app.listen(process.env.PORT);
logToFile('API started using port ' + process.env.PORT)