# Provider

<https://github.com/netlify/gotrue/blob/master/api/provider/provider.go>

```go
type Provider interface {
    AuthCodeURL(string, ...oauth2.AuthCodeOption) string
}

// OAuthProvider specifies additional methods needed for providers using OAuth
type OAuthProvider interface {
    AuthCodeURL(string, ...oauth2.AuthCodeOption) string
    GetUserData(context.Context, *oauth2.Token) (*UserProvidedData, error)
    GetOAuthToken(string) (*oauth2.Token, error)
}
```

在 gotrue 中，provider 是服务于 API 层的，用于整合所有外部登录的方式（包括 OAuth2、SAML）。
在 Auth Portal 中，类似 AuthCodeURL 可能不必在 provider 中实现，前期应当更专注于 GetUserData 的实现。
