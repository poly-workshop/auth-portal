# Mailer

<https://github.com/netlify/gotrue/tree/master/mailer>

```go
// Mailer defines the interface a mailer must implement.
type Mailer interface {
    Send(user *models.User, subject, body string, data map[string]interface{}) error
    InviteMail(user *models.User, referrerURL string) error
    ConfirmationMail(user *models.User, referrerURL string) error
    RecoveryMail(user *models.User, referrerURL string) error
    EmailChangeMail(user *models.User, referrerURL string) error
    ValidateEmail(email string) error
}
```

Mailer 接口定义了邮件发送器必须实现的方法，包括发送邀请邮件、确认邮件、恢复邮件和更改邮箱邮件等功能。

在 gotrue 中依赖了一个 github.com/netlify/mailme 的库，但实际内容非常少，短期可以考虑集成在项目中，长期可以考虑替换为更成熟的邮件发送库。
