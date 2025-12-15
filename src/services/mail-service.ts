import nodemailer from "nodemailer";
import config from "@/common/app-config";

const transporter = nodemailer.createTransport({
    service: "gmail",
    host: "mail.myserver.com",
    port: 587,
    secure: false,
    auth: {
        user: config.EMAIL,
        pass: config.GMAIL_PASSWORD,
    },
    tls: {
        rejectUnauthorized: false,
    },
});

const getAdminSignUpHTMLContent = () => {
    return `
    <!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f8f7ff;
            color: #333;
            margin: 0;
            padding: 0;
        }

        .container {
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .header {
            background-color: #d6a6ff;
            color: #fff;
            text-align: center;
            padding: 20px;
            border-radius: 8px;
        }

        .header h1 {
            margin: 0;
            font-size: 28px;
        }

        .content {
            padding: 20px;
        }

        .content p {
            font-size: 16px;
            line-height: 1.5;
            margin: 10px 0;
        }

        .footer {
            text-align: center;
            font-size: 14px;
            color: #777;
            margin-top: 10px;
        }

        .footer a {
            color: #d6a6ff;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>KMA Scanner</h1>
        </div>

        <div class="content">
            <p>Chào bạn,</p>
            <p>Cảm ơn bạn đã đăng ký tài khoản tại <strong>KMA Scanner</strong>! Bạn đã hoàn tất quá trình đăng ký và giờ có thể bắt đầu sử dụng ứng dụng của chúng tôi dưới vai trò là 1 Admin.</p>
            <p>Chúng tôi rất vui khi bạn là một phần của cộng đồng <strong>KMA Scanner</strong>. Nếu bạn cần hỗ trợ hay có bất kỳ câu hỏi nào, đừng ngần ngại liên hệ với chúng tôi!</p>
            <p>Chúc bạn sử dụng ứng dụng hiệu quả và tiện lợi!</p>
        </div>

        <div class="footer">
            <p>Thân ái, <br>Đội ngũ KMA Scanner</p>
        </div>
    </div>
</body>
</html>
  `;
};

const sendEmail = async (
    toEmail: string,
    subject: string,
    htmlContent: string
) => {
    const mailOptions = {
        from: config.EMAIL,
        to: toEmail,
        subject: subject,
        html: htmlContent,
    };

    console.log(config.EMAIL, config.GMAIL_PASSWORD);

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log("Email sent: " + info.response);
    } catch (error) {
        console.error(error);
        throw new Error("Send mail failed: " + error);
    }
};

const getOTPHTMLContent = (otp: string) => {
    return `
    <!doctype html>
    <html lang="vi">
        <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f9e5a4;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }

                .container {
                    width: 100%;
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                }

                .header {
                    background-color: #ffd600; /* Màu vàng đậm */
                    text-align: center;
                    padding: 20px;
                    border-radius: 8px;
                }

                .header h1 {
                    margin: 0;
                    font-size: 28px;
                    color: #ffffff;
                }

                .content {
                    padding: 20px;
                }

                .content p {
                    font-size: 16px;
                    line-height: 1.5;
                    margin: 10px 0;
                }

                .footer {
                    text-align: center;
                    font-size: 14px;
                    color: #555;
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>KMA Scanner thông báo</h1>
                </div>

                <div class="content">
                    <p> Mã xác thực của bạn là: 
                        <strong>${otp}</strong>, tránh để lộ ra ngoài. Mã có hiệu lực trong vòng 2 phút.
                    </p>
                    <p>
                        Nếu bạn cần hỗ trợ hay có bất kỳ câu hỏi nào, đừng ngần ngại
                        liên hệ với chúng tôi!
                    </p>
                    <p>Chúc bạn sử dụng trang web hiệu quả và tiện lợi!</p>
                </div>

                <div class="footer">
                    <p>Thân ái, <br />Đội ngũ HG Store</p>
                </div>
            </div>
        </body>
    </html>
  `;
};

export default {
    sendEmail,
    getSignUpGmailNotify: getAdminSignUpHTMLContent,
    getOTPHTMLContent,
};
