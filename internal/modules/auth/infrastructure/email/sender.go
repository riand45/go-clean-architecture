// Package email provides email sending service using SMTP.
package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/smtp"
	"time"

	"github.com/dummy-event/internal/config"
	"github.com/dummy-event/internal/modules/auth/domain/service"
)

// Ensure implementation satisfies interface
var _ service.EmailService = (*SMTPEmailService)(nil)

// SMTPEmailService implements EmailService using SMTP
type SMTPEmailService struct {
	host     string
	port     int
	user     string
	password string
	from     string
	fromName string
}

// NewSMTPEmailService creates a new SMTPEmailService
func NewSMTPEmailService(cfg *config.SMTPConfig) *SMTPEmailService {
	return &SMTPEmailService{
		host:     cfg.Host,
		port:     cfg.Port,
		user:     cfg.User,
		password: cfg.Password,
		from:     cfg.From,
		fromName: cfg.FromName,
	}
}

// SendOTP sends OTP code to the specified email address
func (s *SMTPEmailService) SendOTP(ctx context.Context, email, otpCode string) error {
	subject := "Your Login Verification Code"

	// Generate HTML body from template
	body, err := s.generateOTPEmail(otpCode)
	if err != nil {
		return fmt.Errorf("failed to generate email body: %w", err)
	}

	return s.sendEmail(ctx, email, subject, body)
}

// SendWelcome sends a welcome email to new users
func (s *SMTPEmailService) SendWelcome(ctx context.Context, email, name string) error {
	subject := "Welcome to Dummy Event!"

	body, err := s.generateWelcomeEmail(name)
	if err != nil {
		return fmt.Errorf("failed to generate email body: %w", err)
	}

	return s.sendEmail(ctx, email, subject, body)
}

// sendEmail sends an email using SMTP
func (s *SMTPEmailService) sendEmail(ctx context.Context, to, subject, htmlBody string) error {
	// Create a channel to handle timeout
	done := make(chan error, 1)

	go func() {
		// Build message
		headers := make(map[string]string)
		headers["From"] = fmt.Sprintf("%s <%s>", s.fromName, s.from)
		headers["To"] = to
		headers["Subject"] = subject
		headers["MIME-Version"] = "1.0"
		headers["Content-Type"] = "text/html; charset=UTF-8"

		var message bytes.Buffer
		for k, v := range headers {
			message.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
		message.WriteString("\r\n")
		message.WriteString(htmlBody)

		// SMTP authentication
		auth := smtp.PlainAuth("", s.user, s.password, s.host)

		// Send email
		addr := fmt.Sprintf("%s:%d", s.host, s.port)
		err := smtp.SendMail(addr, auth, s.from, []string{to}, message.Bytes())
		done <- err
	}()

	// Wait for completion or context cancellation
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("failed to send email: %w", err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("email sending cancelled: %w", ctx.Err())
	case <-time.After(30 * time.Second):
		return fmt.Errorf("email sending timeout")
	}
}

// generateOTPEmail generates the OTP email HTML body
func (s *SMTPEmailService) generateOTPEmail(otpCode string) (string, error) {
	const otpTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background-color: #f9f9f9;
            border-radius: 10px;
            padding: 30px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .otp-code {
            background-color: #4f46e5;
            color: white;
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            padding: 20px;
            text-align: center;
            border-radius: 10px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-top: 30px;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 5px;
            padding: 10px;
            margin-top: 20px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Login Verification</h1>
        </div>
        <p>Hello,</p>
        <p>We received a request to log in to your account. Use the following verification code:</p>
        <div class="otp-code">{{.OTPCode}}</div>
        <p>This code will expire in <strong>5 minutes</strong>.</p>
        <div class="warning">
            ⚠️ If you didn't request this code, please ignore this email. Someone may have entered your email address by mistake.
        </div>
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>&copy; 2024 Dummy Event. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`

	tmpl, err := template.New("otp").Parse(otpTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]string{"OTPCode": otpCode})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// generateWelcomeEmail generates the welcome email HTML body
func (s *SMTPEmailService) generateWelcomeEmail(name string) (string, error) {
	const welcomeTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background-color: #f9f9f9;
            border-radius: 10px;
            padding: 30px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .footer {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome to Dummy Event!</h1>
        </div>
        <p>Hello {{.Name}},</p>
        <p>Thank you for joining Dummy Event! We're excited to have you on board.</p>
        <p>You can now explore all the features and start using our platform.</p>
        <div class="footer">
            <p>&copy; 2024 Dummy Event. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`

	tmpl, err := template.New("welcome").Parse(welcomeTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]string{"Name": name})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
