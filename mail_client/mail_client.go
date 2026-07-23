package mailClient

import (
	"fmt"
	"go/playground/config"

	"github.com/wneessen/go-mail"
)

type ContentType int

const (
	Text ContentType = iota
	HTML
)

type MailClient struct {
	client *mail.Client
}

func Init(conf config.SMTP) (MailClient, error) {
	var smtp MailClient = MailClient{}
	c, err := mail.NewClient(conf.Client,
		mail.WithPort(conf.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(conf.Username),
		mail.WithPassword(conf.Password),
	)
	if err != nil {
		return smtp, err
	}
	smtp = MailClient{
		client: c,
	}

	return smtp, nil
}

func (mc MailClient) SendMail(from, to, message, subject string, contentType ContentType) error {
	m := mail.NewMsg()
	if err := m.From(from); err != nil {
		return fmt.Errorf("failed to set From address: %w", err)
	}
	if err := m.To(to); err != nil {
		return fmt.Errorf("failed to set To address: %w", err)
	}
	m.Subject(subject)

	var ct mail.ContentType

	switch contentType {
	case HTML:
		ct = mail.TypeTextHTML
	case Text:
		ct = mail.TypeTextHTML
	default:
		ct = mail.TypeTextPlain
	}

	m.SetBodyString(ct, message)

	err := mc.client.DialAndSend(m)
	if err != nil {
		return fmt.Errorf("faild to send the email: %w", err)
	}
	return nil
}
