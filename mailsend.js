require('dotenv').config();
const nodemailer = require('nodemailer');
// テストメールアドレス
const toAddress = 'applehaakaiyo@gmail.com'

//export用にfunction設定を追加
module.exports = function(verificationUrl) {
    // メール送信設定
    const transporter = nodemailer.createTransport({
        host: process.env.MAIL_HOST,
        port: process.env.MAIL_PORT,
        secure: process.env.MAIL_SECURE,
        auth: {
        user: 'applehaakaiyo@gmail.com',
        pass: 'Ryuta0919'
        }
    });

    // メール内容を登録

    const mailOptions1 = {
        from: process.env.MAIL_USER,
        to: toAddress,
        subject: '本登録メール',
        text: "以下のURLをクリックして本登録を完了させてください。\n\n"+ verificationUrl
    };


    // 本登録メールを送信
    transporter.sendMail(mailOptions1, function (error, info) {
        if (error) {
        console.log(error);
        } else {
        console.log('Email sent: ' + info.response);
        }
    });
  
}; 