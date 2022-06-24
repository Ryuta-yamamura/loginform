const express = require('express');
const app = express();

const mustacheExpress = require('mustache-express');
app.engine('mst', mustacheExpress());
app.set('view engine', 'mst');
app.set('views', __dirname + '/views');



// ログアウト機能の実装
app.get('/logout', (req, res, next) => {
    // req.logout();
    res.redirect('/login');
 });
 

 module.exports = logout;