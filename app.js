require('dotenv').config();
const express = require('express');
const app = express();
const passport = require('./auth');
const session = require('express-session');
const flash = require('connect-flash');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const User = require('./models').User;
const mailsendModule = require('./mailsend');

app.use(cookieParser());

// 暗号化につかうキー
const APP_KEY = 'YOUR-SECRET-KEY';

// トップURL
const APP_URL = process.env.APPURL;

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

// バリデーション・ルール
const registrationValidationRules = [
  check('name')
    .not().isEmpty().withMessage('この項目は必須入力です。'),
  check('email')
    .not().isEmpty().withMessage('この項目は必須入力です。')
    .isEmail().withMessage('有効なメールアドレス形式で指定してください。'),
  check('password')
    .not().isEmpty().withMessage('この項目は必須入力です。')
    .isLength({ min:8, max:25 }).withMessage('8文字から25文字にしてください。')
    .custom((value, { req }) => {

      if(req.body.password !== req.body.passwordConfirmation) {

        throw new Error('パスワード（確認）と一致しません。');

      }

      return true;

    })
];

// ここに先ほどの事前データ

app.post('/register', registrationValidationRules, (req, res) => {

  const errors = validationResult(req);

  if(!errors.isEmpty()) { // バリデーション失敗

    return res.status(422).json({ errors: errors.array() });

  }

  // 送信されたデータ
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  // ユーザーデータを登録（仮登録）
  User.findOrCreate({
    where: { email: email },
    defaults: {
      name: name,
      email: email,
      password: bcrypt.hashSync(password, bcrypt.genSaltSync(8))
    }
  }).then(([user]) => {

    if(user.emailVerifiedAt) { // すでに登録されている時

      return res.status(422).json({
        errors: [
          {
            value: email,
            msg: 'すでに登録されています。',
            param: 'email',
            location: 'body'
          }
        ]
      });

    }
    // 本登録URLを作成
    const hash = crypto.createHash('sha1')
      .update(user.email)
      .digest('hex');
    const now = new Date();
    const expiration = now.setHours(now.getHours() + 1); // 1時間だけ有効
    let verificationUrl = APP_URL +'/verify/'+ user.id +'/'+ hash +'?expires='+ expiration;
    const signature = crypto.createHmac('sha256', APP_KEY)
      .update(verificationUrl)
      .digest('hex');
    verificationUrl += '&signature='+ signature;
    console.log(verificationUrl);

    // メール送信用モデュールの設定
    mailsendModule(verificationUrl);

    return res.json({
      result: true
    });

  });

});

app.get('/verify/:id/:hash', (req, res) => {

  const userId = req.params.id;
  User.findByPk(userId)
    .then(user => {

      if(!user) {

        res.status(422).send('このURLは正しくありません。');

      } else if(user.emailVerifiedAt) {  // すでに本登録が完了している場合

        // ログイン＆リダイレクト（Passport.js）
        req.login(user, () => res.redirect('/user'));

      } else {

        const now = new Date();
        const hash = crypto.createHash('sha1')
          .update(user.email)
          .digest('hex');
        const isCorrectHash = (hash === req.params.hash);
        const isExpired = (now.getTime() > parseInt(req.query.expires));
        const verificationUrl = APP_URL + req.originalUrl.split('&signature=')[0];
        const signature = crypto.createHmac('sha256', APP_KEY)
          .update(verificationUrl)
          .digest('hex');
        const isCorrectSignature = (signature === req.query.signature);

        if(!isCorrectHash || !isCorrectSignature || isExpired) {

          res.status(422).send('このURLはすでに有効期限切れか、正しくありません。');

        } else {  // 本登録

          user.emailVerifiedAt = new Date();
          user.save();

          // ログイン＆リダイレクト（Passport.js）
          req.login(user, () => res.redirect('/user'));

        }

      }

    });

});

// 5000番ポートで待機
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`${PORT}番のポートで待機中です...`);
});