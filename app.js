require('dotenv').config();
const express = require('express');
const app = express();
const passport = require('./auth');
const session = require('express-session');
const flash = require('connect-flash');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { check, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const User = require('./models').User;

app.use(cookieParser());

// 暗号化につかうキー
const APP_KEY = 'YOUR-SECRET-KEY';
// ミドルウェアの設定(EXPRESSのPOSTデータの取得)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(flash());
app.use(session({
  secret: 'YOUR-SECRET-STRING',
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// テンプレート
const mustacheExpress = require('mustache-express');
app.engine('mst', mustacheExpress());
app.set('view engine', 'mst');
app.set('views', __dirname + '/views');


const authMiddleware = (req, res, next) => {
  if(req.isAuthenticated()) { // ログインしてるかチェック

    next();

  } else if(req.cookies.remember_me) {

    const [rememberToken, hash] = req.cookies.remember_me.split('|');

    User.findAll({
      where: {
        rememberToken: rememberToken
      }
    }).then(users => {

      for(let i in users) {

        const user = users[i];

        const verifyingHash = crypto.createHmac('sha256', APP_KEY)
          .update(user.id +'-'+ rememberToken)
          .digest('hex');

        if(hash === verifyingHash) {

          return req.login(user, () => {

            // セキュリティ的はここで remember_me を再度更新すべき

            next();

          });

        }


      }

      res.redirect(302, '/login');

    });

  } else {

    res.redirect(302, '/login');

  }
};

// ログインフォーム
app.get('/login', (req, res) => {
  const errorMessage = req.flash('error').join('<br>');
  res.render('login/form', {
    errorMessage: errorMessage
  });
});

// ログイン実行
app.post('/login',
  passport.authenticate('local', {
    failureRedirect: '/login',
    failureFlash: true,
    badRequestMessage: '「メールアドレス」と「パスワード」は必須入力です。'
  }),
  (req, res, next) => {

    if(!req.body.remember) {  // 次回もログインを省略しない場合

      res.clearCookie('remember_me');
      return next();

    }

    const user = req.user;
    const rememberToken = crypto.randomBytes(20).toString('hex'); // ランダムな文字列
    const hash = crypto.createHmac('sha256', APP_KEY)
      .update(user.id +'-'+ rememberToken)
      .digest('hex');
    user.rememberToken = rememberToken;
    user.save();

    res.cookie('remember_me', rememberToken +'|'+ hash, {
      path: '/',
      maxAge: 5 * 365 * 24 * 60 * 60 * 1000 // 5年
    });

    return next();

  },
  (req, res) => {

    res.redirect('/user');

  }
);

// ログイン成功後のページ
app.get('/user', authMiddleware, (req, res) => {
  const user = req.user;
  // res.send('ログイン完了！');
  res.render('user/user');

});

// ログアウト機能の実装
app.get('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) { 
      return next(err); 
    }
    res.redirect('/login');
  });
});

// 新規登録フォームの実装
app.get('/register', (req, res) => {

  return res.render('auth/register');

});

// 5000番ポートで待機
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`${PORT}番のポートで待機中です...`);
});